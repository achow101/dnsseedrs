#![feature(ip)]

use base32ct::{Base32Unpadded, Encoding};
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::p2p::address::{Address, AddrV2};
use bitcoin::p2p::Magic;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::ServiceFlags;
use clap::Parser;
use sha3::{Digest, Sha3_256};
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream};
use std::str::FromStr;
use std::time;
use std::thread;

use rusqlite::params;

#[derive(Parser)]
#[command(version, about, long_about)]
struct Args {
    #[arg(short, long)]
    seednode: Vec<String>,

    #[arg(short, long)]
    db_file: Option<String>,
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

fn parse_address(addr: String) -> Result<NodeAddress, &'static str> {
    let addr_parse_res = SocketAddr::from_str(&addr);
    if addr_parse_res.is_ok() {
        let parsed_addr = addr_parse_res.unwrap();
        let ip = parsed_addr.ip().to_canonical();
        if ip.is_ipv4() {
            if !ip.is_global() {
                return Err("IPv4 addresses must be globally accessible");
            }
            if let IpAddr::V4(ip4) = ip {
                return Ok(NodeAddress {
                    host: Host::Ipv4(ip4),
                    port: parsed_addr.port(),
                });
            }
        }
        assert!(ip.is_ipv6());
        if let IpAddr::V6(ip6) = ip {
            if !ip6.is_global() {
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

fn crawl_node(db_conn: &rusqlite::Connection, addr: String) {
    let node_addr = parse_address(addr).unwrap();
    let sock = match node_addr.host {
        Host::Ipv4(ip) => {
            TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V4(ip), node_addr.port), time::Duration::from_secs(10)).unwrap()
        },
        Host::Ipv6(ip) | Host::CJDNS(ip) => {
            TcpStream::connect_timeout(&SocketAddr::new(IpAddr::V6(ip), node_addr.port), time::Duration::from_secs(10)).unwrap()
        },
        Host::OnionV3(ref host) => {
            let stream = TcpStream::connect(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9050)).unwrap();
            socks5_connect(&stream, &host, node_addr.port).unwrap();
            stream
        },
        Host::I2P(ref host) => {
            let stream = TcpStream::connect(&SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 4447)).unwrap();
            socks5_connect(&stream, &host, node_addr.port).unwrap();
            stream
        },
    };

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
            },
            NetworkMessage::Addr(addrs) => {
                for (_, a) in addrs {
                    println!("Got addrv1 {}:{} with service flags {}", Ipv6Addr::from(a.address), a.port, a.services);
                }
                break
            },
            NetworkMessage::AddrV2(addrs) => {
                for a in addrs {
                    let addrstr = match a.addr {
                        AddrV2::Ipv4(ip) => ip.to_string(),
                        AddrV2::Ipv6(ip) => ip.to_string(),
                        AddrV2::TorV2(host) => "who's advertising torv2????".to_string(),
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

                            (Base32Unpadded::encode_string(&to_enc) + ".onion").to_string()
                        },
                        AddrV2::I2p(host) => (Base32Unpadded::encode_string(&host) + ".b32.i2p").to_string(),
                        AddrV2::Cjdns(ip) => ip.to_string(),
                        _ => "unknown".to_string(),
                    };
                    println!("Got addrv2 {}:{} with service flags {}", addrstr, a.port, a.services);
                }
                break
            },
            NetworkMessage::Ping(ping) => {
                RawNetworkMessage::new(net_magic, NetworkMessage::Pong(*ping)).consensus_encode(&mut write_stream).unwrap();
            },
            _ => (),
        };
        write_stream.flush().unwrap();
    }

    sock.shutdown(Shutdown::Both).unwrap();
}

fn main() {
    let args = Args::parse();

    let db_file = args.db_file.unwrap_or("sqlite.db".to_string());

    let db_conn = rusqlite::Connection::open(&db_file).unwrap();
    db_conn.execute("CREATE TABLE if NOT EXISTS 'nodes' (address TEXT PRIMARY KEY, last_tried INTEGER, last_seen INTEGER, user_agent TEXT, services INTEGER, starting_height INTEGER)", []).unwrap();
    db_conn.execute("CREATE TABLE if NOT EXISTS 'tried_log' (address TEXT, timestamp INTEGER, online BOOL, FOREIGN KEY(address) REFERENCES nodes(address))", []).unwrap();

    let mut new_node_stmt = db_conn.prepare("INSERT OR IGNORE INTO nodes VALUES(?, NULL, NULL, NULL, NULL, NULL)").unwrap();
    for arg in args.seednode {
        new_node_stmt.execute([arg]).unwrap();
    }

    let mut select_next_node = db_conn.prepare("SELECT address FROM nodes ORDER BY last_tried ASC LIMIT 1").unwrap();
    let mut update_last_tried = db_conn.prepare("UPDATE nodes SET last_tried = ? WHERE address = ?").unwrap();
    loop {
        let node: String = select_next_node.query_row([], |r| r.get(0),).unwrap();
        select_next_node.clear_bindings();

        update_last_tried.execute(params![time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap().as_secs(), node]).unwrap();
        update_last_tried.clear_bindings();

        crawl_node(&db_conn, node);
        thread::sleep(time::Duration::from_secs(1));
    }
}
