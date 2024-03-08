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
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::time;
use std::thread;
use threadpool::ThreadPool;

use rusqlite::params;

#[derive(Parser)]
#[command(version, about, long_about)]
struct Args {
    #[arg(short, long)]
    seednode: Vec<String>,

    #[arg(long)]
    db_file: Option<String>,

    #[arg(long)]
    dump_file: Option<String>,

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

    #[arg(short, long, default_value_t = 24)]
    threads: usize,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum Host {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    CJDNS(Ipv6Addr),
    OnionV3(String),
    I2P(String),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct NodeAddress {
    host: Host,
    port: u16,
}

impl ToString for NodeAddress {
    fn to_string(&self) -> String {
        match &self.host {
            Host::Ipv4(ip) => format!("{}:{}", ip.to_string(), self.port),
            Host::Ipv6(ip) | Host::CJDNS(ip) => format!("[{}]:{}", ip.to_string(), self.port),
            Host::OnionV3(s) | Host::I2P(s) => format!("{}:{}", s, self.port),
        }
    }
}


#[derive(Debug, Clone)]
struct NodeInfo {
    addr: NodeAddress,
    last_tried: u64,
    last_seen: u64,
    user_agent: String,
    services: u64,
    starting_height: i32,
    protocol_version: u32,
    try_count: i64,
    reliability_2h: f64,
    reliability_8h: f64,
    reliability_1d: f64,
    reliability_1w: f64,
    reliability_1m: f64,
}

impl NodeInfo {
    fn new(addr: String) -> Result<NodeInfo, String> {
        return Self::construct(addr, 0, 0, "".to_string(), 0, 0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0);
    }

    fn construct(
        addr_str: String,
        last_tried: u64,
        last_seen: u64,
        user_agent: String,
        services: u64,
        starting_height: i32,
        protocol_version: u32,
        try_count: i64,
        reliability_2h: f64,
        reliability_8h: f64,
        reliability_1d: f64,
        reliability_1w: f64,
        reliability_1m: f64,
    ) -> Result<NodeInfo, String> {
        match parse_address(&addr_str) {
            Ok(a) => Ok(NodeInfo{
                addr: a,
                last_tried: last_tried,
                last_seen: last_seen,
                user_agent: user_agent,
                services: services,
                starting_height: starting_height,
                protocol_version: protocol_version,
                try_count: try_count,
                reliability_2h: reliability_2h,
                reliability_8h: reliability_8h,
                reliability_1d: reliability_1d,
                reliability_1w: reliability_1w,
                reliability_1m: reliability_1m,
            }),
            Err(e) => Err(e.to_string()),
        }
    }
}

struct CrawlInfo {
    node_info: NodeInfo,
    age: u64,
}

#[derive(Clone)]
struct NetStatus {
    ipv4: bool,
    ipv6: bool,
    cjdns: bool,
    onion_proxy: Option<String>,
    i2p_proxy: Option<String>,
}

enum CrawledNode {
    Failed(CrawlInfo),
    UpdatedInfo(CrawlInfo),
    NewNode(CrawlInfo),
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

fn crawl_node(send_channel: SyncSender<CrawledNode>, node: NodeInfo, net_status: NetStatus) {
    println!("Crawling {}", &node.addr.to_string());

    let tried_timestamp = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap().as_secs();
    let age = tried_timestamp - node.last_tried;

    let sock_res = match node.addr.host {
        Host::Ipv4(ip) if net_status.ipv4 => {
            TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(ip), node.addr.port), time::Duration::from_secs(10))
        },
        Host::Ipv6(ip) if net_status.ipv6 => {
            TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V6(ip), node.addr.port), time::Duration::from_secs(10))
        },
        Host::CJDNS(ip) if net_status.cjdns => {
            TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V6(ip), node.addr.port), time::Duration::from_secs(10))
        },
        Host::OnionV3(ref host) if net_status.onion_proxy.is_some() => {
            let proxy_addr = net_status.onion_proxy.as_ref().unwrap();
            let stream = TcpStream::connect_timeout(&SocketAddr::from_str(&proxy_addr).unwrap(), time::Duration::from_secs(10));
            if stream.is_ok() {
                let cr = socks5_connect(&stream.as_ref().unwrap(), &host, node.addr.port);
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
                let cr = socks5_connect(&stream.as_ref().unwrap(), &host, node.addr.port);
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
        let mut node_info = node.clone();
        node_info.last_tried = tried_timestamp;
        send_channel.send(CrawledNode::Failed(CrawlInfo{node_info: node_info, age: age})).unwrap();
        return ();
    }
    let sock = sock_res.unwrap();

    // Return error so we can update with failed try
    let ret: Result<(), std::io::Error> = (|| {
        let mut write_stream = BufWriter::new(&sock);
        let mut read_stream = BufReader::new(&sock);

        let net_magic = Magic::BITCOIN;

        // Prep Version message
        let addr_them = match &node.addr.host {
            Host::Ipv4(ip) => Address{ services: ServiceFlags::NONE, address: ip.to_ipv6_mapped().segments(), port: node.addr.port },
            Host::Ipv6(ip) => Address{ services: ServiceFlags::NONE, address: ip.segments(), port: node.addr.port },
            Host::OnionV3(..) | Host::I2P(..) | Host::CJDNS(..) => Address{ services: ServiceFlags::NONE, address: [0, 0, 0, 0, 0, 0, 0, 0], port: node.addr.port },
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
        RawNetworkMessage::new(net_magic, NetworkMessage::Version(ver_msg)).consensus_encode(&mut write_stream)?;

        // Send sendaddrv2 message
        RawNetworkMessage::new(net_magic, NetworkMessage::SendAddrV2{}).consensus_encode(&mut write_stream)?;
        write_stream.flush().unwrap();

        // Receive loop
        loop {
            let msg = match RawNetworkMessage::consensus_decode(&mut read_stream) {
                Ok(m) => m,
                Err(e) => {
                    return Err(std::io::Error::other(e.to_string()));
                },
            };
            match msg.payload() {
                NetworkMessage::Version(ver) => {
                    // Send verack
                    RawNetworkMessage::new(net_magic, NetworkMessage::Verack{}).consensus_encode(&mut write_stream)?;

                    // Send getaddr
                    RawNetworkMessage::new(net_magic, NetworkMessage::GetAddr{}).consensus_encode(&mut write_stream)?;

                    let mut new_info = node.clone();
                    new_info.last_tried = tried_timestamp;
                    new_info.last_seen = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap().as_secs();
                    new_info.user_agent = ver.user_agent.clone();
                    new_info.services = ver.services.to_u64();
                    new_info.starting_height = ver.start_height;
                    new_info.protocol_version = ver.version;
                    match send_channel.send(CrawledNode::UpdatedInfo(CrawlInfo{node_info: new_info, age: age})) {
                        Ok(..) => (),
                        Err(e) => {
                            return Err(std::io::Error::other(e.to_string()));
                        },
                    };
                },
                NetworkMessage::Addr(addrs) => {
                    println!("Received addrv1 from {}", &node.addr.to_string());
                    for (_, a) in addrs {
                        match a.socket_addr() {
                            Ok(s) => {
                                match NodeInfo::new(s.to_string()) {
                                    Ok(mut new_info) => {
                                        new_info.services = a.services.to_u64();
                                        match send_channel.send(CrawledNode::NewNode(CrawlInfo{node_info: new_info, age: 0})) {
                                            Ok(..) => (),
                                            Err(e) => {
                                                return Err(std::io::Error::other(e.to_string()));
                                            },
                                        };
                                    },
                                    Err(..) => (),
                                }
                            },
                            Err(..) => {},
                        };
                    }
                    break
                },
                NetworkMessage::AddrV2(addrs) => {
                    println!("Received addrv2 from {}", &node.addr.to_string());
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
                                match NodeInfo::new(s.to_string()) {
                                    Ok(mut new_info) => {
                                        new_info.services = a.services.to_u64();
                                        match send_channel.send(CrawledNode::NewNode(CrawlInfo{node_info: new_info, age: 0})) {
                                            Ok(..) => (),
                                            Err(e) => {
                                                return Err(std::io::Error::other(e.to_string()));
                                            },
                                        };
                                    },
                                    Err(..) => (),
                                }
                            },
                            Err(e) => println!("Error: {}", e),
                        }
                    }
                    break
                },
                NetworkMessage::Ping(ping) => {
                    RawNetworkMessage::new(net_magic, NetworkMessage::Pong(*ping)).consensus_encode(&mut write_stream)?;
                },
                _ => ()
            };
            write_stream.flush().unwrap();
        }
        return Ok(());
    })();

    if ret.is_err() {
        let mut node_info = node.clone();
        node_info.last_tried = tried_timestamp;
        send_channel.send(CrawledNode::Failed(CrawlInfo{node_info: node_info, age: age})).unwrap();
    }

    sock.shutdown(Shutdown::Both).unwrap();
}

fn calculate_reliability(good: bool, old_reliability: f64, age: u64, window: u64) -> f64 {
    let alpha = 1.0 - (-1.0 * age as f64 / window as f64).exp(); // 1 - e^(-delta T / tau)
    let x = if good { 1.0 } else { 0.0 };
    return (alpha * x) + ((1.0 - alpha) * old_reliability); // alpha * x + (1 - alpha) * s_{t-1}
}

fn is_good(node: &NodeInfo) -> bool {
    if node.addr.port != 8333 {
        return false;
    }
    if !ServiceFlags::from(node.services).has(ServiceFlags::NETWORK) {
        return false;
    }
    if node.protocol_version < 70001 {
        return false;
    }
    if node.starting_height < 350000 {
        return false;
    }

    if node.reliability_2h > 0.85 && node.try_count > 2 {
        return true;
    }
    if node.reliability_8h > 0.70 && node.try_count > 4 {
        return true;
    }
    if node.reliability_1d > 0.55 && node.try_count > 8 {
        return true;
    }
    if node.reliability_1w > 0.45 && node.try_count > 16 {
        return true;
    }
    if node.reliability_1m > 0.35 && node.try_count > 32 {
        return true;
    }

    return false;
}

fn crawler_thread(db_conn: Arc<Mutex<rusqlite::Connection>>, threads: usize, net_status: NetStatus) {
    // Setup thread pool with one less than specified to account for this thread.
    let pool = ThreadPool::new(threads - 1);

    // Shared between fetcher and finisher thread
    let nodes_in_flight: Arc<Mutex<HashSet<NodeAddress>>> = Arc::new(Mutex::new(HashSet::new()));

    // Finisher thread to receive newly found addrs and update node info and try
    let (tx, rx) = sync_channel::<CrawledNode>(threads * 1000 * 2);
    let f_db_conn = db_conn.clone();
    let f_nin_flight = nodes_in_flight.clone();
    pool.execute(move || {
        let mut i = 0;
        loop {
            let crawled = rx.recv().unwrap();
            let locked_db_conn = f_db_conn.lock().unwrap();
            if i == 0 {
                locked_db_conn.execute("BEGIN TRANSACTION", []).unwrap();
            }
            if i == 500 {
                locked_db_conn.execute("COMMIT TRANSACTION", []).unwrap();
                i = -1;
            }
            match crawled {
                CrawledNode::Failed(info) => {
                    locked_db_conn.execute("
                        UPDATE nodes SET
                            last_tried = ?,
                            try_count = ?,
                            reliability_2h = ?,
                            reliability_8h = ?,
                            reliability_1d = ?,
                            reliability_1w = ?,
                            reliability_1m = ?
                        WHERE address = ?",
                        params![
                            info.node_info.last_tried,
                            info.node_info.try_count + 1,
                            calculate_reliability(false, info.node_info.reliability_2h, info.age, 3600 * 2),
                            calculate_reliability(false, info.node_info.reliability_8h, info.age, 3600 * 8),
                            calculate_reliability(false, info.node_info.reliability_1d, info.age, 3600 * 24),
                            calculate_reliability(false, info.node_info.reliability_1w, info.age, 3600 * 24 * 7),
                            calculate_reliability(false, info.node_info.reliability_1m, info.age, 3600 * 24 * 30),
                            info.node_info.addr.to_string(),
                        ]
                    ).unwrap();
                    f_nin_flight.lock().unwrap().remove(&info.node_info.addr);
                },
                CrawledNode::UpdatedInfo(info) => {
                    locked_db_conn.execute(
                        "UPDATE nodes SET
                            last_tried = ?,
                            last_seen = ?,
                            user_agent = ?,
                            services = ?,
                            starting_height = ?,
                            protocol_version = ?,
                            try_count = ?,
                            reliability_2h = ?,
                            reliability_8h = ?,
                            reliability_1d = ?,
                            reliability_1w = ?,
                            reliability_1m = ?
                        WHERE address = ?",
                        params![
                            info.node_info.last_tried,
                            info.node_info.last_seen,
                            info.node_info.user_agent,
                            info.node_info.services.to_be_bytes(),
                            info.node_info.starting_height,
                            info.node_info.protocol_version,
                            info.node_info.try_count + 1,
                            calculate_reliability(true, info.node_info.reliability_2h, info.age, 3600 * 2),
                            calculate_reliability(true, info.node_info.reliability_8h, info.age, 3600 * 8),
                            calculate_reliability(true, info.node_info.reliability_1d, info.age, 3600 * 24),
                            calculate_reliability(true, info.node_info.reliability_1w, info.age, 3600 * 24 * 7),
                            calculate_reliability(true, info.node_info.reliability_1m, info.age, 3600 * 24 * 30),
                            info.node_info.addr.to_string(),
                        ]
                    ).unwrap();
                    f_nin_flight.lock().unwrap().remove(&info.node_info.addr);
                },
                CrawledNode::NewNode(info) => {
                    locked_db_conn.execute(
                        "INSERT OR IGNORE INTO nodes VALUES(?, 0, 0, '', ?, 0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0)",
                        params![&info.node_info.addr.to_string(), info.node_info.services.to_be_bytes()]
                    ).unwrap();
                    f_nin_flight.lock().unwrap().remove(&info.node_info.addr);
                },
            }
            i += 1;
        }
    });

    // Queue to send nodes to crawl to the crawler threads
    let queue = ArrayQueue::new(threads * 2);
    let arc_queue = Arc::new(queue);

    // Work fetcher loop
    loop {
        let ten_min_ago = (time::SystemTime::now().duration_since(time::SystemTime::UNIX_EPOCH).unwrap() - time::Duration::from_secs(60 * 10)).as_secs();
        let nodes: Vec<NodeInfo>;
        {
            let locked_db_conn = db_conn.lock().unwrap();
            let mut select_next_nodes = locked_db_conn.prepare("SELECT * FROM nodes WHERE last_tried < ? ORDER BY last_tried").unwrap();
            let node_iter = select_next_nodes.query_map([ten_min_ago], |r| {
                Ok(NodeInfo::construct(
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    u64::from_be_bytes(r.get(4)?),
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                    r.get(11)?,
                    r.get(12)?,
                ))
            }).unwrap();
            nodes = node_iter.filter_map(|n| {
                match n {
                    Ok(ni) => match ni {
                        Ok(nni) => Some(nni),
                        Err(..) => None,
                    },
                    Err(..) => None,
                }
            }).collect();
        }
        for node in nodes {
            while arc_queue.is_full() {
                thread::sleep(time::Duration::from_secs(1));
            }

            {
                let mut l_nodes_in_flight = nodes_in_flight.lock().unwrap();
                if l_nodes_in_flight.get(&node.addr).is_some() {
                    continue;
                }
                l_nodes_in_flight.insert(node.addr.clone());
            }

            arc_queue.push(node).unwrap();

            if pool.active_count() < pool.max_count() {
                let net_status_c: NetStatus = net_status.clone();
                let queue_c = arc_queue.clone();
                let tx_c = tx.clone();
                pool.execute(move || {
                    loop {
                        while queue_c.is_empty() {
                            thread::sleep(time::Duration::from_secs(1));
                        }
                        let next_node = queue_c.pop().unwrap();
                        crawl_node(tx_c.clone(), next_node, net_status_c.clone());
                    }
                });
            }
        }
        thread::sleep(time::Duration::from_secs(1));
    }
}

fn dumper_thread(db_conn: Arc<Mutex<rusqlite::Connection>>, dump_file: &String) {
    let mut count = 0;
    loop {
        // Sleep for 100s, then 200s, 400s, 800s, 1600s, and then 3200s forever
        thread::sleep(time::Duration::from_secs(100 << count));
        if count < 5 {
            count += 1;
        }

        let nodes: Vec<NodeInfo>;
        {
            let locked_db_conn = db_conn.lock().unwrap();
            let mut select_nodes = locked_db_conn.prepare("SELECT * FROM nodes WHERE try_count > 0").unwrap();
            let node_iter = select_nodes.query_map([], |r| {
                Ok(NodeInfo::construct(
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                    r.get(11)?,
                    r.get(12)?,
                ))
            }).unwrap();
            nodes = node_iter.filter_map(|n| {
                match n {
                    Ok(ni) => match ni {
                        Ok(nni) => Some(nni),
                        Err(..) => None,
                    },
                    Err(..) => None,
                }
            }).collect();
        }

        let mut f = File::create(dump_file).unwrap();
        write!(f,
            "{:<70}{:<6}{:<12}{:^8}{:^8}{:^8}{:^8}{:^8}{:^9}{:<18}{:<8}{}\n",
            "address",
            "good",
            "last_seen",
            "%(2h)",
            "%(8h)",
            "%(1d)",
            "%(1w)",
            "%(1m)",
            "blocks",
            "services",
            "version",
            "user_agent"
        ).unwrap();
        for node in nodes {
            write!(f,
                "{:<70}{:<6}{:<12}{:>6.2}% {:>6.2}% {:>6.2}% {:>6.2}% {:>7.2}% {:<8}{:0>16x}  {:<8}{}\n",
                node.addr.to_string(),
                i32::from(is_good(&node)),
                node.last_seen,
                node.reliability_2h * 100.0,
                node.reliability_8h * 100.0,
                node.reliability_1d * 100.0,
                node.reliability_1w * 100.0,
                node.reliability_1m * 100.0,
                node.starting_height,
                node.services,
                node.protocol_version,
                node.user_agent,
            ).unwrap();
        }
    }
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
                protocol_version INTEGER NOT NULL,
                try_count INTEGER NOT NULL,
                reliability_2h REAL NOT NULL,
                reliability_8h REAL NOT NULL,
                reliability_1d REAL NOT NULL,
                reliability_1w REAL NOT NULL,
                reliability_1m REAL NOT NULL
            )",
            []
        ).unwrap();

        let mut new_node_stmt = locked_db_conn.prepare("INSERT OR IGNORE INTO nodes VALUES(?, 0, 0, '', ?, 0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0)").unwrap();
        for arg in args.seednode {
            new_node_stmt.execute(params![arg, 0_u64.to_be_bytes()]).unwrap();
        }
    }

    // Start crawler threads
    let db_conn_c = db_conn.clone();
    let net_status_c: NetStatus = net_status.clone();
    let t_crawl = thread::spawn(move || {
        crawler_thread(db_conn_c, args.threads - 3, net_status_c);
    });

    // Start dumper thread
    let dump_file = args.dump_file.unwrap_or("seeds.txt".to_string());
    let db_conn_c2 = db_conn.clone();
    let t_dump = thread::spawn(move || {
        dumper_thread(db_conn_c2, &dump_file);
    });

    // Join all threads
    t_dump.join().unwrap();
    t_crawl.join().unwrap();
}
