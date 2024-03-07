use base32ct::{Base32Unpadded, Encoding};
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::p2p::address::{Address, AddrV2};
use bitcoin::p2p::Magic;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::ServiceFlags;
use crossbeam::queue::ArrayQueue;
use clap::Parser;
use sha3::{Digest, Sha3_256};
use std::collections::HashSet;
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time;
use std::thread;
use threadpool::ThreadPool;

use rusqlite::params;

#[derive(Parser)]
#[command(version, about, long_about)]
struct Args {
    #[arg(short, long)]
    seednode: Vec<String>,

    #[arg(short, long)]
    db_file: Option<String>,

    #[arg(long, default_value_t = true)]
    ipv4_reachable: bool,

    #[arg(long, default_value_t = true)]
    ipv6_reachable: bool,

    #[arg(short, long, default_value_t = false)]
    cjdns_reachable: bool,

    #[arg(short, long, default_value = "127.0.0.1:9050")]
    onion_proxy: String,

    #[arg(short, long, default_value = "127.0.0.1:4447")]
    i2p_proxy: String,

    #[arg(short, long, default_value_t = 20)]
    threads: usize,
}

enum Host {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    CJDNS(Ipv6Addr),
    OnionV3(String),
    I2P(String),
}

struct NodeAddress {
    host: Host,
    port: u16,
}

#[derive(Debug)]
struct NodeInfo {
    addr_str: String,
    last_tried: u64,
    last_seen: u64,
    user_agent: String,
    services: u64,
    starting_height: i32,
    protocol_version: i32,
}

#[derive(Clone)]
struct NetStatus {
    ipv4: bool,
    ipv6: bool,
    cjdns: bool,
    onion_proxy: Option<String>,
    i2p_proxy: Option<String>,
}

fn parse_address(addr: &String) -> Result<NodeAddress, &'static str> {
    let addr_parse_res = SocketAddr::from_str(&addr);
    if addr_parse_res.is_ok() {
        let parsed_addr = addr_parse_res.unwrap();
        let ip = parsed_addr.ip().to_canonical();
        if let IpAddr::V4(ip4) = ip {
            // Similar to is_global(), but not unstable only feature
            if ip4.octets()[0] == 0
                || ip4.is_private()
                || ip4.is_loopback()
                || ip4.is_link_local()
                || (ip4.octets()[0] == 192 && ip4.octets()[1] == 0 && ip4.octets()[2] ==0)
                || ip4.is_documentation()
                || ip4.is_broadcast()
            {
                return Err("IPv4 addresses must be globally accessible");
            }
            return Ok(NodeAddress {
                host: Host::Ipv4(ip4),
                port: parsed_addr.port(),
            });
        }
        assert!(ip.is_ipv6());
        if let IpAddr::V6(ip6) = ip {
            // Similar to is_global(), but not unstable only feature
            if ip6.is_unspecified()
                || matches!(ip6.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
                || matches!(ip6.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
                || matches!(ip6.segments(), [0x100, 0, 0, 0, _, _, _, _])
                || (matches!(ip6.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
                    && !(
                        u128::from_be_bytes(ip6.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
                        || u128::from_be_bytes(ip6.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
                        || matches!(ip6.segments(), [0x2001, 3, _, _, _, _, _, _])
                        || matches!(ip6.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
                        || matches!(ip6.segments(), [0x2001, b, _, _, _, _, _, _] if b >= 0x20 && b <= 0x2F)
                    ))
            {
                // Check for CJDNS in fc00::/8
                if matches!(ip6.octets(), [0xfc, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _]) {
                    return Ok(NodeAddress {
                        host: Host::CJDNS(ip6),
                        port: parsed_addr.port(),
                    });
                }
                return Err("IPv6 addresses must be globally accessible or CJDNS");
            }
            return Ok(NodeAddress {
                host: Host::Ipv6(ip6),
                port: parsed_addr.port(),
            });
        }
    }
    let sp: Vec<&str> = addr.split(":").collect();
    if sp.len() != 2 {
        return Err("Invalid address, not IPv6 and multiple colons or colon not found");
    }
    let host = &sp[0];
    let port = sp[1].parse::<u16>().unwrap();
    if host.len() == 62 && host.ends_with(".onion") {
        return Ok(NodeAddress{
            host: Host::OnionV3(host.to_string()),
            port: port,
        });
    }
    if host.len() == 60 && host.ends_with(".b32.i2p") {
        return Ok(NodeAddress{
            host: Host::I2P(host.to_string()),
            port: port,
        });
    }
    return Err("Invalid address");
}

fn socks5_connect(sock: &TcpStream, destination: &String, port: u16) -> Result<(), &'static str> {
    let mut write_stream = BufWriter::new(sock);
    let mut read_stream = BufReader::new(sock);

    // Send first socks message
    // Version (0x05) | Num Auth Methods (0x01) | Auth Method NoAuth (0x00)
    write_stream.write(&[0x05, 0x01, 0x00]).unwrap();
    write_stream.flush().unwrap();

    // Get Server's chosen auth method
    let mut server_auth_method: [u8; 2] = [0; 2];
    read_stream.read_exact(&mut server_auth_method).unwrap();
    if server_auth_method[0] != 0x05 {
        return Err("Server responded with unexpected Socks version");
    }
    if server_auth_method[1] != 0x00 {
        return Err("Server responded with unsupported auth method");
    }

    // Send request
    // Version (0x05) | Connect Command (0x01) | Reserved (0x00) | Domain name address type (0x03)
    write_stream.write(&[0x05, 0x01, 0x00, 0x03]).unwrap();
    // The destination we want the server to connect to
    write_stream.write(&[u8::try_from(destination.len()).unwrap()]).unwrap();
    write_stream.write(destination.as_bytes()).unwrap();
    write_stream.write(&port.to_be_bytes()).unwrap();
    write_stream.flush().unwrap();

    // Get reply
    let mut server_reply: [u8; 4] = [0; 4];
    read_stream.read_exact(&mut server_reply).unwrap();
    if server_reply[0] != 0x05 {
        return Err("Server responded with unsupported auth method");
    }
    if server_reply[1] != 0x00 {
        return Err("Server could not connect to destination");
    }
    if server_reply[2] != 0x00 {
        return Err("Server responded with unexpected reserved value");
    }
    if server_reply[3] == 0x01 {
        let mut server_bound_addr: [u8; 4] = [0; 4];
        read_stream.read_exact(&mut server_bound_addr).unwrap();
    } else if server_reply[3] == 0x03 {
        let mut server_bound_addr_len: [u8; 1] = [0; 1];
        read_stream.read_exact(&mut server_bound_addr_len).unwrap();
        let mut server_bound_addr = vec![0u8; usize::from(server_bound_addr_len[0])];
        read_stream.read_exact(&mut server_bound_addr).unwrap();
    } else if server_reply[3] == 0x04 {
        let mut server_bound_addr: [u8; 16] = [0; 16];
        read_stream.read_exact(&mut server_bound_addr).unwrap();
    }

    return Ok(());
}

fn crawl_node(db_conn: Arc<Mutex<rusqlite::Connection>>, node: NodeInfo, net_status: NetStatus) {
    println!("Crawling {}", &node.addr_str);

    let tried_timestamp = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap().as_secs();
    {
        // Update last tried now to avoid getting these again next time around
        let locked_db_conn = db_conn.lock().unwrap();
        locked_db_conn.execute("UPDATE nodes SET last_tried = ? WHERE address = ?", params![tried_timestamp, &node.addr_str]).unwrap();
    }

    let node_addr = parse_address(&node.addr_str).unwrap();
    let sock_res = match node_addr.host {
        Host::Ipv4(ip) if net_status.ipv4 => {
            TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(ip), node_addr.port), time::Duration::from_secs(10))
        },
        Host::Ipv6(ip) if net_status.ipv6 => {
            TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V6(ip), node_addr.port), time::Duration::from_secs(10))
        },
        Host::CJDNS(ip) if net_status.cjdns => {
            TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V6(ip), node_addr.port), time::Duration::from_secs(10))
        },
        Host::OnionV3(ref host) if net_status.onion_proxy.is_some() => {
            let proxy_addr = net_status.onion_proxy.as_ref().unwrap();
            let stream = TcpStream::connect_timeout(&SocketAddr::from_str(&proxy_addr).unwrap(), time::Duration::from_secs(10));
            if stream.is_ok() {
                let cr = socks5_connect(&stream.as_ref().unwrap(), &host, node_addr.port);
                match cr {
                    Ok(..) => stream,
                    Err(e) => Err(std::io::Error::other(e)),
                }
            } else {
                stream
            }
        },
        Host::I2P(ref host) if net_status.i2p_proxy.is_some() => {
            let proxy_addr = net_status.i2p_proxy.as_ref().unwrap();
            let stream = TcpStream::connect_timeout(&SocketAddr::from_str(&proxy_addr).unwrap(), time::Duration::from_secs(10));
            if stream.is_err() {
                let cr = socks5_connect(&stream.as_ref().unwrap(), &host, node_addr.port);
                match cr {
                    Ok(..) => stream,
                    Err(e) => Err(std::io::Error::other(e)),
                }
            } else {
                stream
            }
        },
        _ => Err(std::io::Error::other("Net not available"))
    };
    if sock_res.is_err() {
        let locked_db_conn = db_conn.lock().unwrap();
        locked_db_conn.execute("INSERT INTO tried_log VALUES(?, ?, ?)", params![node.addr_str, tried_timestamp, false]).unwrap();
        return ();
    }
    let sock = sock_res.unwrap();

    let mut write_stream = BufWriter::new(&sock);
    let mut read_stream = BufReader::new(&sock);

    let net_magic = Magic::BITCOIN;

    // Prep Version message
    let addr_them = match &node_addr.host {
        Host::Ipv4(ip) => Address{ services: ServiceFlags::NONE, address: ip.to_ipv6_mapped().segments(), port: node_addr.port },
        Host::Ipv6(ip) => Address{ services: ServiceFlags::NONE, address: ip.segments(), port: node_addr.port },
        Host::OnionV3(..) | Host::I2P(..) | Host::CJDNS(..) => Address{ services: ServiceFlags::NONE, address: [0, 0, 0, 0, 0, 0, 0, 0], port: node_addr.port },
    };
    let addr_me = Address{
        services: ServiceFlags::NONE,
        address: [0, 0, 0, 0, 0, 0, 0, 0],
        port: 0,
    };
    let ver_msg = VersionMessage{
        version: 70016,
        services: ServiceFlags::NONE,
        timestamp: i64::try_from(time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap().as_secs()).unwrap(),
        receiver: addr_them,
        sender: addr_me,
        nonce: 0,
        user_agent: "/crawlrs:0.1.0/".to_string(),
        start_height: -1,
        relay: false,
    };

    // Send version message
    RawNetworkMessage::new(net_magic, NetworkMessage::Version(ver_msg)).consensus_encode(&mut write_stream).unwrap();

    // Send sendaddrv2 message
    RawNetworkMessage::new(net_magic, NetworkMessage::SendAddrV2{}).consensus_encode(&mut write_stream).unwrap();
    write_stream.flush().unwrap();

    // Receive loop
    loop {
        let msg = RawNetworkMessage::consensus_decode(&mut read_stream).unwrap();
        match msg.payload() {
            NetworkMessage::Version(ver) => {
                // Send verack
                RawNetworkMessage::new(net_magic, NetworkMessage::Verack{}).consensus_encode(&mut write_stream).unwrap();

                // Send getaddr
                RawNetworkMessage::new(net_magic, NetworkMessage::GetAddr{}).consensus_encode(&mut write_stream).unwrap();

                let locked_db_conn = db_conn.lock().unwrap();
                locked_db_conn.execute(
                    "UPDATE nodes SET last_seen = ?, user_agent = ?, services = ?, starting_height = ?, protocol_version = ? WHERE address = ?",
                    params![
                        time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap().as_secs(),
                        ver.user_agent,
                        ver.services.to_u64().to_be_bytes(),
                        ver.start_height,
                        ver.version,
                        node.addr_str,
                    ]
                ).unwrap();
                locked_db_conn.execute("INSERT INTO tried_log VALUES(?, ?, ?)", params![node.addr_str, tried_timestamp, true]).unwrap();
                println!("Success {}", &node.addr_str);
            },
            NetworkMessage::Addr(addrs) => {
                println!("Received addrv1 from {}", &node.addr_str);
                for (_, a) in addrs {
                    match a.socket_addr() {
                        Ok(s) => {
                            let locked_db_conn = db_conn.lock().unwrap();
                            locked_db_conn.execute(
                                "INSERT OR IGNORE INTO nodes VALUES(?, 0, 0, '', ?, 0, 0)",
                                params![s.to_string(), a.services.to_u64().to_be_bytes()]
                            ).unwrap();
                            println!("Got addrv1 {} with service flags {}", s.to_string(), a.services);
                        },
                        Err(..) => {},
                    };
                }
                break
            },
            NetworkMessage::AddrV2(addrs) => {
                println!("Received addrv2 from {}", &node.addr_str);
                for a in addrs {
                    let addrstr = match a.addr {
                        AddrV2::Ipv4(..) | AddrV2::Ipv6(..) => {
                            match a.socket_addr() {
                                Ok(s) => Ok(s.to_string()),
                                Err(..) => Err("IP type address couldn't be turned into SocketAddr")
                            }
                        },
                        AddrV2::Cjdns(ip) => Ok(format!("[{}]:{}", ip.to_string(), &a.port.to_string())),
                        AddrV2::TorV2(..) => Err("who's advertising torv2????"),
                        AddrV2::TorV3(host) => {
                            let mut to_hash: Vec<u8> = vec![];
                            to_hash.extend_from_slice(b".onion checksum");
                            to_hash.extend_from_slice(&host);
                            to_hash.push(0x03);
                            let checksum = Sha3_256::new()
                                .chain_update(to_hash)
                                .finalize();

                            let mut to_enc: Vec<u8> = vec![];
                            to_enc.extend_from_slice(&host);
                            to_enc.extend_from_slice(&checksum[0..2]);
                            to_enc.push(0x03);

                            Ok(format!("{}.onion:{}", Base32Unpadded::encode_string(&to_enc).trim_matches(char::from(0)), &a.port.to_string()).to_string())
                        },
                        AddrV2::I2p(host) => Ok(format!("{}.b32.i2p:{}", Base32Unpadded::encode_string(&host), &a.port.to_string()).to_string()),
                        _ => Err("unknown"),
                    };
                    match addrstr {
                        Ok(s) => {
                            let locked_db_conn = db_conn.lock().unwrap();
                            locked_db_conn.execute(
                                "INSERT OR IGNORE INTO nodes VALUES(?, 0, 0, '', ?, 0, 0)",
                                params![s.to_string(), a.services.to_u64().to_be_bytes()]
                            ).unwrap();
                        }
                        Err(e) => println!("Error: {}", e),
                    }
                }
                break
            },
            NetworkMessage::Ping(ping) => {
                RawNetworkMessage::new(net_magic, NetworkMessage::Pong(*ping)).consensus_encode(&mut write_stream).unwrap();
            },
            _ => ()
        };
        write_stream.flush().unwrap();
    }

    sock.shutdown(Shutdown::Both).unwrap();
}

fn main() {
    let args = Args::parse();

    let db_file = args.db_file.unwrap_or("sqlite.db".to_string());

    // Check proxies
    println!("Checking onion proxy");
    let mut onion_proxy = Some(&args.onion_proxy);
    let onion_proxy_check = TcpStream::connect_timeout(&SocketAddr::from_str(&args.onion_proxy).unwrap(), time::Duration::from_secs(10));
    if onion_proxy_check.is_ok() {
        if socks5_connect(&onion_proxy_check.as_ref().unwrap(), &"duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion".to_string(), 80).is_err() {
            onion_proxy = None;
        }
        onion_proxy_check.unwrap().shutdown(Shutdown::Both).unwrap();
    } else {
        onion_proxy = None;
    }
    match onion_proxy {
        Some(..) => println!("Onion proxy good"),
        None => println!("Onion proxy bad"),
    }

    println!("Checking I2P proxy");
    let mut i2p_proxy = Some(&args.i2p_proxy);
    let i2p_proxy_check = TcpStream::connect_timeout(&SocketAddr::from_str(&args.i2p_proxy).unwrap(), time::Duration::from_secs(10));
    if i2p_proxy_check.is_ok() {
        if socks5_connect(&i2p_proxy_check.as_ref().unwrap(), &"gqt2klvr6r2hpdfxzt4bn2awwehsnc7l5w22fj3enbauxkhnzcoq.b32.i2p".to_string(), 80).is_err() {
            i2p_proxy = None;
            println!("I2P proxy couldn't connect to test server");
        }
        i2p_proxy_check.unwrap().shutdown(Shutdown::Both).unwrap();
    } else {
        println!("I2P proxy didn't connect");
        i2p_proxy = None;
    }
    match i2p_proxy {
        Some(..) => println!("I2P proxy good"),
        None => println!("I2P proxy bad"),
    }

    let net_status = NetStatus {
        ipv4: args.ipv4_reachable,
        ipv6: args.ipv4_reachable,
        cjdns: args.cjdns_reachable,
        onion_proxy: onion_proxy.cloned(),
        i2p_proxy: i2p_proxy.cloned(),
    };

    let db_conn = Arc::new(Mutex::new(rusqlite::Connection::open(&db_file).unwrap()));
    {
        let locked_db_conn = db_conn.lock().unwrap();
        locked_db_conn.busy_handler(Some(|_| {
            thread::sleep(time::Duration::from_secs(1));
            return true;
        })).unwrap();
        locked_db_conn.execute(
            "CREATE TABLE if NOT EXISTS 'nodes' (
                address TEXT PRIMARY KEY,
                last_tried INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                user_agent TEXT NOT NULL,
                services BLOB NOT NULL,
                starting_height INTEGER NOT NULL,
                protocol_version INTEGER NOT NULL
            )",
            []
        ).unwrap();
        locked_db_conn.execute(
            "CREATE TABLE if NOT EXISTS 'tried_log' (
                address TEXT,
                timestamp INTEGER NOT NULL,
                online BOOL NOT NULL,
                FOREIGN KEY(address) REFERENCES nodes(address)
            )",
            []
        ).unwrap();

        let mut new_node_stmt = locked_db_conn.prepare("INSERT OR IGNORE INTO nodes VALUES(?, 0, 0, '', ?, 0, 0)").unwrap();
        for arg in args.seednode {
            new_node_stmt.execute(params![arg, 0_u64.to_be_bytes()]).unwrap();
        }
    }

    let pool = ThreadPool::new(args.threads);
    let queue = ArrayQueue::new(args.threads * 2);
    let arc_queue = Arc::new(queue);

    // Work fetcher loop
    let mut nodes_in_flight: HashSet<String> = HashSet::new();
    loop {
        let ten_min_ago = (time::SystemTime::now().duration_since(time::SystemTime::UNIX_EPOCH).unwrap() - time::Duration::from_secs(60 * 10)).as_secs();
        let mut nodes: Vec<NodeInfo> = vec![];
        {
            let locked_db_conn = db_conn.lock().unwrap();
            let mut select_next_nodes = locked_db_conn.prepare("SELECT * FROM nodes WHERE last_tried < ? ORDER BY last_tried").unwrap();
            let node_iter = select_next_nodes.query_map([ten_min_ago], |r| {
                Ok(NodeInfo {
                    addr_str: r.get(0)?,
                    last_tried: r.get(1)?,
                    last_seen: r.get(2)?,
                    user_agent: r.get(3)?,
                    services: u64::from_be_bytes(r.get(4)?),
                    starting_height: r.get(5)?,
                    protocol_version: r.get(6)?,
                })
            }).unwrap();
            for n in node_iter {
                nodes.push(n.unwrap());
            }
        }
        for node in nodes {
            if nodes_in_flight.get(&node.addr_str).is_some() {
                continue;
            }
            while arc_queue.is_full() {
                thread::sleep(time::Duration::from_secs(1));
            }

            nodes_in_flight.insert(node.addr_str.clone());

            arc_queue.push(node).unwrap();

            let db_conn_c = db_conn.clone();
            let net_status_c: NetStatus = net_status.clone();
            let queue_c = arc_queue.clone();
            pool.execute(move || {
                while queue_c.is_empty() {
                    thread::sleep(time::Duration::from_secs(1));
                }
                let next_node = queue_c.pop().unwrap();
                crawl_node(db_conn_c, next_node, net_status_c);
            });
        }
        thread::sleep(time::Duration::from_secs(1));
    }
}
