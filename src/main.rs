mod common;
mod dns;

use crate::common::{is_good, Host, NodeAddress, NodeInfo};
use crate::dns::dns_thread;

use std::{
    collections::HashSet,
    fs::{File, rename},
    io::{BufReader, BufWriter, Read, Write},
    net::{IpAddr, Shutdown, SocketAddr, TcpStream},
    path::Path,
    str::FromStr,
    sync::{
        mpsc::{sync_channel, SyncSender},
        Arc, Mutex,
    },
    thread, time,
};

use base32ct::{Base32Unpadded, Encoding};
use bitcoin::{
    consensus::{Decodable, Encodable},
    network::Network,
    p2p::{
        address::{AddrV2, Address},
        message::{NetworkMessage, RawNetworkMessage},
        message_network::VersionMessage,
        ServiceFlags,
    },
};
use clap::Parser;
use crossbeam::queue::ArrayQueue;
use flate2::{write::GzEncoder, Compression};
use rusqlite::params;
use sha3::{Digest, Sha3_256};
use threadpool::ThreadPool;

#[derive(Parser)]
#[command(version, about, long_about)]
struct Args {
    #[arg(short, long)]
    seednode: Vec<String>,

    #[arg(long, default_value = "sqlite.db")]
    db_file: String,

    #[arg(long, default_value = "seeds.txt")]
    dump_file: String,

    #[arg(long, default_value_t = false)]
    no_ipv4: bool,

    #[arg(long, default_value_t = false)]
    no_ipv6: bool,

    #[arg(short, long, default_value_t = false)]
    cjdns_reachable: bool,

    #[arg(short, long, default_value = "127.0.0.1:9050")]
    onion_proxy: String,

    #[arg(short, long, default_value = "127.0.0.1:4447")]
    i2p_proxy: String,

    #[arg(short, long, default_value_t = 24)]
    threads: usize,

    #[arg(short, long, default_value = "0.0.0.0")]
    address: String,

    #[arg(short, long, default_value_t = 53)]
    port: u16,

    #[arg(long, default_value = "main")]
    chain: String,

    /// The path to a directory containing DNSSEC keys produced by dnssec-keygen
    #[arg(long)]
    dnssec_keys: Option<String>,

    /// The domain name for which this server will return results for
    #[arg()]
    seed_domain: String,

    /// The domain name of this server itself, i.e. what the NS record will point to
    #[arg()]
    server_name: String,

    /// The exact string to place in the rname field of the SOA record
    #[arg()]
    soa_rname: String,
}

struct CrawlInfo {
    node_info: NodeInfo,
    age: u64,
}

#[derive(Clone)]
struct NetStatus {
    chain: Network,
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

fn socks5_connect(sock: &TcpStream, destination: &String, port: u16) -> Result<(), &'static str> {
    let mut write_stream = BufWriter::new(sock);
    let mut read_stream = BufReader::new(sock);

    // Send first socks message
    // Version (0x05) | Num Auth Methods (0x01) | Auth Method NoAuth (0x00)
    write_stream.write_all(&[0x05, 0x01, 0x00]).unwrap();
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
    write_stream.write_all(&[0x05, 0x01, 0x00, 0x03]).unwrap();
    // The destination we want the server to connect to
    write_stream
        .write_all(&[u8::try_from(destination.len()).unwrap()])
        .unwrap();
    write_stream.write_all(destination.as_bytes()).unwrap();
    write_stream.write_all(&port.to_be_bytes()).unwrap();
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

    Ok(())
}

fn crawl_node(send_channel: SyncSender<CrawledNode>, node: NodeInfo, net_status: NetStatus) {
    let tried_timestamp = time::SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let age = tried_timestamp - node.last_tried;

    let sock_res = match node.addr.host {
        Host::Ipv4(ip) if net_status.ipv4 => TcpStream::connect_timeout(
            &SocketAddr::new(IpAddr::V4(ip), node.addr.port),
            time::Duration::from_secs(10),
        ),
        Host::Ipv6(ip) if net_status.ipv6 => TcpStream::connect_timeout(
            &SocketAddr::new(IpAddr::V6(ip), node.addr.port),
            time::Duration::from_secs(10),
        ),
        Host::CJDNS(ip) if net_status.cjdns => TcpStream::connect_timeout(
            &SocketAddr::new(IpAddr::V6(ip), node.addr.port),
            time::Duration::from_secs(10),
        ),
        Host::OnionV3(ref host) if net_status.onion_proxy.is_some() => {
            let proxy_addr = net_status.onion_proxy.as_ref().unwrap();
            let stream = TcpStream::connect_timeout(
                &SocketAddr::from_str(proxy_addr).unwrap(),
                time::Duration::from_secs(10),
            );
            if stream.is_ok() {
                let cr = socks5_connect(stream.as_ref().unwrap(), host, node.addr.port);
                match cr {
                    Ok(..) => stream,
                    Err(e) => Err(std::io::Error::other(e)),
                }
            } else {
                stream
            }
        }
        Host::I2P(ref host) if net_status.i2p_proxy.is_some() => {
            let proxy_addr = net_status.i2p_proxy.as_ref().unwrap();
            let stream = TcpStream::connect_timeout(
                &SocketAddr::from_str(proxy_addr).unwrap(),
                time::Duration::from_secs(10),
            );
            if stream.is_err() {
                let cr = socks5_connect(stream.as_ref().unwrap(), host, node.addr.port);
                match cr {
                    Ok(..) => stream,
                    Err(e) => Err(std::io::Error::other(e)),
                }
            } else {
                stream
            }
        }
        _ => Err(std::io::Error::other("Net not available")),
    };
    if sock_res.is_err() {
        let mut node_info = node.clone();
        node_info.last_tried = tried_timestamp;
        send_channel
            .send(CrawledNode::Failed(CrawlInfo { node_info, age }))
            .unwrap();
        return;
    }
    let sock = sock_res.unwrap();

    println!("Crawling {}", &node.addr.to_string());

    // Return error so we can update with failed try
    let ret: Result<(), std::io::Error> = (|| {
        let mut write_stream = BufWriter::new(&sock);
        let mut read_stream = BufReader::new(&sock);

        let net_magic = net_status.chain.magic();

        // Prep Version message
        let addr_them = match &node.addr.host {
            Host::Ipv4(ip) => Address {
                services: ServiceFlags::NONE,
                address: ip.to_ipv6_mapped().segments(),
                port: node.addr.port,
            },
            Host::Ipv6(ip) => Address {
                services: ServiceFlags::NONE,
                address: ip.segments(),
                port: node.addr.port,
            },
            Host::OnionV3(..) | Host::I2P(..) | Host::CJDNS(..) => Address {
                services: ServiceFlags::NONE,
                address: [0, 0, 0, 0, 0, 0, 0, 0],
                port: node.addr.port,
            },
        };
        let addr_me = Address {
            services: ServiceFlags::NONE,
            address: [0, 0, 0, 0, 0, 0, 0, 0],
            port: 0,
        };
        let ver_msg = VersionMessage {
            version: 70016,
            services: ServiceFlags::NONE,
            timestamp: i64::try_from(
                time::SystemTime::now()
                    .duration_since(time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )
            .unwrap(),
            receiver: addr_them,
            sender: addr_me,
            nonce: 0,
            user_agent: "/crawlrs:0.1.0/".to_string(),
            start_height: -1,
            relay: false,
        };

        // Send version message
        RawNetworkMessage::new(net_magic, NetworkMessage::Version(ver_msg))
            .consensus_encode(&mut write_stream)?;

        // Send sendaddrv2 message
        RawNetworkMessage::new(net_magic, NetworkMessage::SendAddrV2 {})
            .consensus_encode(&mut write_stream)?;
        write_stream.flush().unwrap();

        // Receive loop
        loop {
            let msg = match RawNetworkMessage::consensus_decode(&mut read_stream) {
                Ok(m) => m,
                Err(e) => {
                    return Err(std::io::Error::other(e.to_string()));
                }
            };
            match msg.payload() {
                NetworkMessage::Version(ver) => {
                    // Send verack
                    RawNetworkMessage::new(net_magic, NetworkMessage::Verack {})
                        .consensus_encode(&mut write_stream)?;

                    // Send getaddr
                    RawNetworkMessage::new(net_magic, NetworkMessage::GetAddr {})
                        .consensus_encode(&mut write_stream)?;

                    let mut new_info = node.clone();
                    new_info.last_tried = tried_timestamp;
                    new_info.last_seen = time::SystemTime::now()
                        .duration_since(time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    new_info.user_agent.clone_from(&ver.user_agent);
                    new_info.services = ver.services.to_u64();
                    new_info.starting_height = ver.start_height;
                    new_info.protocol_version = ver.version;
                    match send_channel.send(CrawledNode::UpdatedInfo(CrawlInfo {
                        node_info: new_info,
                        age,
                    })) {
                        Ok(..) => (),
                        Err(e) => {
                            return Err(std::io::Error::other(e.to_string()));
                        }
                    };
                }
                NetworkMessage::Addr(addrs) => {
                    println!("Received addrv1 from {}", &node.addr.to_string());
                    for (_, a) in addrs {
                        if let Ok(s) = a.socket_addr() {
                            if let Ok(mut new_info) = NodeInfo::new(s.to_string()) {
                                new_info.services = a.services.to_u64();
                                match send_channel.send(CrawledNode::NewNode(CrawlInfo {
                                    node_info: new_info,
                                    age: 0,
                                })) {
                                    Ok(..) => (),
                                    Err(e) => {
                                        return Err(std::io::Error::other(e.to_string()));
                                    }
                                };
                            }
                        };
                    }
                    break;
                }
                NetworkMessage::AddrV2(addrs) => {
                    println!("Received addrv2 from {}", &node.addr.to_string());
                    for a in addrs {
                        let addrstr = match a.addr {
                            AddrV2::Ipv4(..) | AddrV2::Ipv6(..) => match a.socket_addr() {
                                Ok(s) => Ok(s.to_string()),
                                Err(..) => {
                                    Err("IP type address couldn't be turned into SocketAddr")
                                }
                            },
                            AddrV2::Cjdns(ip) => Ok(format!("[{}]:{}", ip, &a.port.to_string())),
                            AddrV2::TorV2(..) => Err("who's advertising torv2????"),
                            AddrV2::TorV3(host) => {
                                let mut to_hash: Vec<u8> = vec![];
                                to_hash.extend_from_slice(b".onion checksum");
                                to_hash.extend_from_slice(&host);
                                to_hash.push(0x03);
                                let checksum = Sha3_256::new().chain_update(to_hash).finalize();

                                let mut to_enc: Vec<u8> = vec![];
                                to_enc.extend_from_slice(&host);
                                to_enc.extend_from_slice(&checksum[0..2]);
                                to_enc.push(0x03);

                                Ok(format!(
                                    "{}.onion:{}",
                                    Base32Unpadded::encode_string(&to_enc)
                                        .trim_matches(char::from(0)),
                                    &a.port.to_string()
                                )
                                .to_string())
                            }
                            AddrV2::I2p(host) => Ok(format!(
                                "{}.b32.i2p:{}",
                                Base32Unpadded::encode_string(&host),
                                &a.port.to_string()
                            )
                            .to_string()),
                            _ => Err("unknown"),
                        };
                        match addrstr {
                            Ok(s) => {
                                if let Ok(mut new_info) = NodeInfo::new(s.to_string()) {
                                    new_info.services = a.services.to_u64();
                                    match send_channel.send(CrawledNode::NewNode(CrawlInfo {
                                        node_info: new_info,
                                        age: 0,
                                    })) {
                                        Ok(..) => (),
                                        Err(e) => {
                                            return Err(std::io::Error::other(e.to_string()));
                                        }
                                    };
                                }
                            }
                            Err(e) => println!("Error: {}", e),
                        }
                    }
                    break;
                }
                NetworkMessage::Ping(ping) => {
                    RawNetworkMessage::new(net_magic, NetworkMessage::Pong(*ping))
                        .consensus_encode(&mut write_stream)?;
                }
                _ => (),
            };
            write_stream.flush().unwrap();
        }
        Ok(())
    })();

    if ret.is_err() {
        let mut node_info = node.clone();
        node_info.last_tried = tried_timestamp;
        send_channel
            .send(CrawledNode::Failed(CrawlInfo { node_info, age }))
            .unwrap();
    }

    if let Err(e) = sock.shutdown(Shutdown::Both) {
        eprintln!("Error shutting down socket: {}", e);
    }
}

fn calculate_reliability(good: bool, old_reliability: f64, age: u64, window: u64) -> f64 {
    let alpha = 1.0 - (-1.0 * age as f64 / window as f64).exp(); // 1 - e^(-delta T / tau)
    let x = if good { 1.0 } else { 0.0 };
    (alpha * x) + ((1.0 - alpha) * old_reliability) // alpha * x + (1 - alpha) * s_{t-1}
}

fn crawler_thread(
    db_conn: Arc<Mutex<rusqlite::Connection>>,
    threads: usize,
    mut net_status: NetStatus,
) {
    // Check proxies
    println!("Checking onion proxy");
    let onion_proxy_check = TcpStream::connect_timeout(
        &SocketAddr::from_str(net_status.onion_proxy.as_ref().unwrap()).unwrap(),
        time::Duration::from_secs(10),
    );
    if onion_proxy_check.is_ok() {
        if socks5_connect(
            onion_proxy_check.as_ref().unwrap(),
            &"duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion".to_string(),
            80,
        )
        .is_err()
        {
            net_status.onion_proxy = None;
        }
        onion_proxy_check.unwrap().shutdown(Shutdown::Both).unwrap();
    } else {
        net_status.onion_proxy = None;
    }
    match net_status.onion_proxy {
        Some(..) => println!("Onion proxy good"),
        None => println!("Onion proxy bad"),
    }

    println!("Checking I2P proxy");
    let i2p_proxy_check = TcpStream::connect_timeout(
        &SocketAddr::from_str(net_status.i2p_proxy.as_ref().unwrap()).unwrap(),
        time::Duration::from_secs(10),
    );
    if i2p_proxy_check.is_ok() {
        if socks5_connect(
            i2p_proxy_check.as_ref().unwrap(),
            &"gqt2klvr6r2hpdfxzt4bn2awwehsnc7l5w22fj3enbauxkhnzcoq.b32.i2p".to_string(),
            80,
        )
        .is_err()
        {
            net_status.i2p_proxy = None;
            println!("I2P proxy couldn't connect to test server");
        }
        i2p_proxy_check.unwrap().shutdown(Shutdown::Both).unwrap();
    } else {
        println!("I2P proxy didn't connect");
        net_status.i2p_proxy = None;
    }
    match net_status.i2p_proxy {
        Some(..) => println!("I2P proxy good"),
        None => println!("I2P proxy bad"),
    }

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
        let ten_min_ago = (time::SystemTime::now()
            .duration_since(time::SystemTime::UNIX_EPOCH)
            .unwrap()
            - time::Duration::from_secs(60 * 10))
        .as_secs();
        let nodes: Vec<NodeInfo>;
        {
            let locked_db_conn = db_conn.lock().unwrap();
            let mut select_next_nodes = locked_db_conn
                .prepare("SELECT * FROM nodes WHERE last_tried < ? ORDER BY last_tried")
                .unwrap();
            let node_iter = select_next_nodes
                .query_map([ten_min_ago], |r| {
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
                })
                .unwrap();
            nodes = node_iter
                .filter_map(|n| match n {
                    Ok(ni) => match ni {
                        Ok(nni) => Some(nni),
                        Err(..) => None,
                    },
                    Err(..) => None,
                })
                .collect();
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
                pool.execute(move || loop {
                    while queue_c.is_empty() {
                        thread::sleep(time::Duration::from_secs(1));
                    }
                    let next_node = queue_c.pop().unwrap();
                    crawl_node(tx_c.clone(), next_node, net_status_c.clone());
                });
            }
        }
        thread::sleep(time::Duration::from_secs(1));
    }
}

fn dumper_thread(db_conn: Arc<Mutex<rusqlite::Connection>>, dump_file: &String, chain: &Network) {
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
            let mut select_nodes = locked_db_conn
                .prepare("SELECT * FROM nodes WHERE try_count > 0")
                .unwrap();
            let node_iter = select_nodes
                .query_map([], |r| {
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
                })
                .unwrap();
            nodes = node_iter
                .filter_map(|n| match n {
                    Ok(ni) => match ni {
                        Ok(nni) => Some(nni),
                        Err(e) => {
                            println!("{}", e);
                            None
                        }
                    },
                    Err(e) => {
                        println!("{}", e);
                        None
                    }
                })
                .collect();
        }

        let txt_tmp_path = format!("{}.tmp", dump_file);
        let mut txt_tmp_file = File::create(&txt_tmp_path).unwrap();
        println!("Writing txt to temporary file {}", &txt_tmp_path);
        writeln!(
            txt_tmp_file,
            "{:<70}{:<6}{:<12}{:^8}{:^8}{:^8}{:^8}{:^8}{:^9}{:<18}{:<8}user_agent",
            "# address",
            "good",
            "last_seen",
            "%(2h)",
            "%(8h)",
            "%(1d)",
            "%(1w)",
            "%(1m)",
            "blocks",
            "services",
            "version"
        )
        .unwrap();
        for node in nodes {
            writeln!(txt_tmp_file,
                "{:<70}{:<6}{:<12}{:>6.2}% {:>6.2}% {:>6.2}% {:>6.2}% {:>7.2}% {:<8}{:0>16x}  {:<8}\"{}\"",
                node.addr.to_string(),
                i32::from(is_good(&node, chain)),
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
        println!("Renaming {} to {}", txt_tmp_path, dump_file);
        rename(txt_tmp_path.clone(), dump_file).unwrap();

        // Compress with gz
        let gz_tmp_path = format!("{}.gz.tmp", dump_file);
        println!("Writing gz to temporary file {}", gz_tmp_path);
        let gz_tmp_file = File::create(&gz_tmp_path).unwrap();
        let mut enc = GzEncoder::new(gz_tmp_file, Compression::default());
        let f = File::open(dump_file).unwrap();
        let mut reader = BufReader::new(f);

        let mut buffer = [0; 1024 * 256];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break, // EOF
                Ok(count) => enc.write_all(&buffer[..count]).unwrap(),
                Err(e) => panic!("Failed to read from file: {}", e),
            }
        }
        enc.finish().unwrap();

        let gz_path = format!("{}.gz", dump_file);
        let archive_path = Path::new(&gz_path);
        println!("Renaming {} to {:?}", gz_tmp_path, archive_path);
        rename(gz_tmp_path, archive_path).unwrap();
    }
}

fn main() {
    let args = Args::parse();

    // Pick the network
    let chain_p = Network::from_core_arg(&args.chain);
    match chain_p {
        Ok(Network::Bitcoin) | Ok(Network::Testnet) | Ok(Network::Signet) => (),
        _ => {
            println!("Unsupported network type: {}", args.chain);
            std::process::exit(1);
        }
    }
    let chain = chain_p.unwrap();

    // Check that DNSSEC keys directory is a directory
    if args.dnssec_keys.is_some() && !Path::new(&args.dnssec_keys.as_ref().unwrap()).is_dir() {
        println!("{} is not a directory", args.dnssec_keys.unwrap());
        std::process::exit(1);
    }

    let net_status = NetStatus {
        chain,
        ipv4: !args.no_ipv4,
        ipv6: !args.no_ipv6,
        cjdns: args.cjdns_reachable,
        onion_proxy: Some(args.onion_proxy),
        i2p_proxy: Some(args.i2p_proxy),
    };

    let db_conn = Arc::new(Mutex::new(
        rusqlite::Connection::open(&args.db_file).unwrap(),
    ));
    {
        let locked_db_conn = db_conn.lock().unwrap();
        locked_db_conn
            .busy_handler(Some(|_| {
                thread::sleep(time::Duration::from_secs(1));
                true
            }))
            .unwrap();
        locked_db_conn
            .execute(
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
                [],
            )
            .unwrap();

        let mut new_node_stmt = locked_db_conn.prepare("INSERT OR IGNORE INTO nodes VALUES(?, 0, 0, '', ?, 0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0)").unwrap();
        for arg in args.seednode {
            new_node_stmt
                .execute(params![arg, 0_u64.to_be_bytes()])
                .unwrap();
        }
    }

    // Start crawler threads
    let db_conn_c = db_conn.clone();
    let net_status_c: NetStatus = net_status.clone();
    let t_crawl = thread::spawn(move || {
        crawler_thread(db_conn_c, args.threads - 3, net_status_c);
    });

    // Start dumper thread
    let db_conn_c2 = db_conn.clone();
    let t_dump = thread::spawn(move || {
        dumper_thread(db_conn_c2, &args.dump_file, &chain);
    });

    // Start DNS thread
    let db_conn_c3 = db_conn.clone();
    let t_dns = thread::spawn(move || {
        dns_thread(
            &args.address,
            args.port,
            db_conn_c3,
            &args.seed_domain,
            &args.server_name,
            &args.soa_rname,
            &chain,
            args.dnssec_keys,
        );
    });

    // Watchdog, exit if any main thread has died
    loop {
        if t_crawl.is_finished() || t_dump.is_finished() || t_dns.is_finished() {
            break;
        }
        thread::sleep(time::Duration::from_secs(60));
    }
}
