use crate::common::{Host, NetStatus, NodeAddress, NodeInfo};

use std::{
    collections::HashSet,
    error::Error,
    io::BufReader as StdBufReader,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{Arc, Mutex},
    time,
};

use base32ct::{Base32Unpadded, Encoding};
use bip324::futures::Protocol as V2Protocol;
use bip324::io::Payload;
use bip324::serde::{
    deserialize as V2Deserialize, serialize as V2Serialize, NetworkMessage as V2NetworkMessage,
};
use bitcoin::{
    consensus::{Decodable, Encodable},
    p2p::{
        address::{AddrV2, Address},
        message::{NetworkMessage, RawNetworkMessage, MAX_MSG_SIZE},
        message_network::VersionMessage,
        Magic, ServiceFlags,
    },
};
use rusqlite::params;
use sha3::{Digest, Sha3_256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader as AsyncBufReader},
    net::TcpStream,
    sync::Semaphore,
    time::timeout,
};

struct CrawlInfo {
    node_info: NodeInfo,
    age: u64,
}

enum CrawledNode {
    Failed(CrawlInfo),
    UpdatedInfo(CrawlInfo),
    NewNode(CrawlInfo),
}

#[derive(Debug)]
struct V2ConnectError {}
impl std::fmt::Display for V2ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Faled to connect to peer with P2Pv2")
    }
}
impl Error for V2ConnectError {}

#[derive(Debug)]
struct NetNotAvailableError {}
impl std::fmt::Display for NetNotAvailableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Network not available")
    }
}
impl Error for NetNotAvailableError {}

async fn socks5_connect(
    sock: &mut TcpStream,
    destination: &String,
    port: u16,
) -> Result<(), &'static str> {
    // Send first socks message
    // Version (0x05) | Num Auth Methods (0x01) | Auth Method NoAuth (0x00)
    sock.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    sock.flush().await.unwrap();

    // Get Server's chosen auth method
    let mut server_auth_method: [u8; 2] = [0; 2];
    sock.read_exact(&mut server_auth_method).await.unwrap();
    if server_auth_method[0] != 0x05 {
        return Err("Server responded with unexpected Socks version");
    }
    if server_auth_method[1] != 0x00 {
        return Err("Server responded with unsupported auth method");
    }

    // Send request
    // Version (0x05) | Connect Command (0x01) | Reserved (0x00) | Domain name address type (0x03)
    sock.write_all(&[0x05, 0x01, 0x00, 0x03]).await.unwrap();
    // The destination we want the server to connect to
    sock.write_all(&[u8::try_from(destination.len()).unwrap()])
        .await
        .unwrap();
    sock.write_all(destination.as_bytes()).await.unwrap();
    sock.write_all(&port.to_be_bytes()).await.unwrap();
    sock.flush().await.unwrap();

    // Get reply
    let mut server_reply: [u8; 4] = [0; 4];
    sock.read_exact(&mut server_reply).await.unwrap();
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
        sock.read_exact(&mut server_bound_addr).await.unwrap();
    } else if server_reply[3] == 0x03 {
        let mut server_bound_addr_len: [u8; 1] = [0; 1];
        sock.read_exact(&mut server_bound_addr_len).await.unwrap();
        let mut server_bound_addr = vec![0u8; usize::from(server_bound_addr_len[0])];
        sock.read_exact(&mut server_bound_addr).await.unwrap();
    } else if server_reply[3] == 0x04 {
        let mut server_bound_addr: [u8; 16] = [0; 16];
        sock.read_exact(&mut server_bound_addr).await.unwrap();
    }
    let mut server_bound_port: [u8; 2] = [0; 2];
    sock.read_exact(&mut server_bound_port).await.unwrap();

    Ok(())
}

async fn get_node_addrs_v1(
    sock: &mut TcpStream,
    node: &NodeInfo,
    net_status: &NetStatus,
    tried_timestamp: u64,
    age: u64,
) -> Result<Vec<CrawledNode>, std::io::Error> {
    let mut ret_addrs = Vec::<CrawledNode>::new();
    let mut write_buf = Vec::<u8>::new();
    let (mut read_sock, mut write_sock) = sock.split();

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
        user_agent: "/crawlrs:0.2.0/".to_string(),
        start_height: -1,
        relay: false,
    };

    // Send version message
    RawNetworkMessage::new(net_magic, NetworkMessage::Version(ver_msg))
        .consensus_encode(&mut write_buf)?;

    // Send sendaddrv2 message
    RawNetworkMessage::new(net_magic, NetworkMessage::SendAddrV2 {})
        .consensus_encode(&mut write_buf)?;
    write_sock.write_all(&write_buf).await.unwrap();
    write_sock.flush().await.unwrap();
    write_buf.clear();

    // Receive loop
    let mut reader = AsyncBufReader::new(&mut read_sock);
    loop {
        // Because I can't figure out how to use an async socket with rust-bitcoin's
        // consensus_decode, we're going to read each message with a little bit of decoding
        // from the socket ourselves, then pass it own to consensus_decode

        // Find the magic, always 4 bytes
        let mut msg = vec![0_u8; 4];
        reader.read_exact(msg.as_mut_slice()).await?;
        while msg.as_slice() != <Magic as AsRef<[u8]>>::as_ref(&net_magic) {
            // Remove first byte
            msg.drain(0..1);
            let mut next_byte = [0_u8; 1];
            reader.read_exact(&mut next_byte).await?;
            msg.extend(next_byte);
        }

        // Read command, always 12 bytes
        let mut cmd = [0_u8; 12];
        reader.read_exact(&mut cmd).await?;
        msg.extend(cmd);

        // Read data length
        let mut len_bytes = [0_u8; 4];
        reader.read_exact(&mut len_bytes).await?;
        let data_len = u32::from_le_bytes(len_bytes);
        msg.extend(len_bytes);
        if data_len as usize > MAX_MSG_SIZE {
            return Err(std::io::Error::other("Message exceeds max length"));
        }

        // Read the data
        let mut data: Vec<u8> = vec![0; data_len as usize];
        reader.read_exact(data.as_mut_slice()).await?;
        msg.extend(data);

        // Read the checksum, always 4 bytes
        let mut checksum = [0_u8; 4];
        reader.read_exact(&mut checksum).await?;
        msg.extend(checksum);

        // Now let rust-bitcoin do its decoding
        let mut msg_reader = StdBufReader::new(msg.as_slice());
        let msg = match RawNetworkMessage::consensus_decode(&mut msg_reader) {
            Ok(m) => m,
            Err(e) => {
                return Err(std::io::Error::other(e.to_string()));
            }
        };
        match msg.payload() {
            NetworkMessage::Version(ver) => {
                // Send verack
                RawNetworkMessage::new(net_magic, NetworkMessage::Verack {})
                    .consensus_encode(&mut write_buf)?;

                // Send getaddr
                RawNetworkMessage::new(net_magic, NetworkMessage::GetAddr {})
                    .consensus_encode(&mut write_buf)?;

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
                ret_addrs.push(CrawledNode::UpdatedInfo(CrawlInfo {
                    node_info: new_info,
                    age,
                }));
            }
            NetworkMessage::Addr(addrs) => {
                println!("Received addrv1 from {}", &node.addr.to_string());
                for (_, a) in addrs {
                    if let Ok(s) = a.socket_addr() {
                        if let Ok(mut new_info) = NodeInfo::new(s.to_string()) {
                            new_info.services = a.services.to_u64();
                            ret_addrs.push(CrawledNode::NewNode(CrawlInfo {
                                node_info: new_info,
                                age: 0,
                            }));
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
                            Err(..) => Err("IP type address couldn't be turned into SocketAddr"),
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
                                Base32Unpadded::encode_string(&to_enc).trim_matches(char::from(0)),
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
                                ret_addrs.push(CrawledNode::NewNode(CrawlInfo {
                                    node_info: new_info,
                                    age: 0,
                                }));
                            }
                        }
                        Err(e) => println!("Error: {e}"),
                    }
                }
                break;
            }
            NetworkMessage::Ping(ping) => {
                RawNetworkMessage::new(net_magic, NetworkMessage::Pong(*ping))
                    .consensus_encode(&mut write_buf)?;
            }
            _ => (),
        };
        write_sock.write_all(&write_buf).await.unwrap();
        write_sock.flush().await.unwrap();
        write_buf.clear();
    }
    Ok(ret_addrs)
}
async fn get_node_addrs_v2(
    sock: &mut TcpStream,
    node: &NodeInfo,
    net_status: &NetStatus,
    tried_timestamp: u64,
    age: u64,
) -> Result<Vec<CrawledNode>, Box<dyn Error + Send>> {
    let mut ret_addrs = Vec::<CrawledNode>::new();
    let mut write_buf = Vec::<u8>::new();

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
        user_agent: "/crawlrs:0.2.0/".to_string(),
        start_height: -1,
        relay: false,
    };

    let (read_sock, write_sock) = sock.split();
    let reader = AsyncBufReader::new(read_sock);
    let mut protocol = match V2Protocol::new(
        net_status.chain,
        bip324::Role::Initiator,
        None,
        None, // no garbage or decoys
        reader,
        write_sock,
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            println!("V2 Connection failed {}", e.to_string());
            return Err(Box::new(V2ConnectError {}));
        }
    };

    // Send version and sendaddrv2 messages
    protocol
        .write(&Payload::genuine(V2Serialize(V2NetworkMessage::Version(
            ver_msg,
        ))))
        .await
        .unwrap();
    protocol
        .write(&Payload::genuine(V2Serialize(
            V2NetworkMessage::SendAddrV2 {},
        )))
        .await
        .unwrap();
    write_buf.clear();

    // Receive loop
    loop {
        let response = match protocol.read().await {
            Ok(r) => r,
            Err(e) => {
                return Err(Box::new(std::io::Error::other(e.to_string())));
            }
        };
        let msg = match V2Deserialize(response.contents()) {
            Ok(m) => m,
            Err(e) => {
                return Err(Box::new(std::io::Error::other(e.to_string())));
            }
        };
        match msg {
            NetworkMessage::Version(ver) => {
                // Send verack and getaddr
                protocol
                    .write(&Payload::genuine(V2Serialize(V2NetworkMessage::Verack {})))
                    .await
                    .unwrap();
                protocol
                    .write(&Payload::genuine(V2Serialize(V2NetworkMessage::GetAddr {})))
                    .await
                    .unwrap();

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
                ret_addrs.push(CrawledNode::UpdatedInfo(CrawlInfo {
                    node_info: new_info,
                    age,
                }));
            }
            NetworkMessage::Addr(addrs) => {
                println!("Received addrv1 from {}", &node.addr.to_string());
                for (_, a) in addrs {
                    if let Ok(s) = a.socket_addr() {
                        if let Ok(mut new_info) = NodeInfo::new(s.to_string()) {
                            new_info.services = a.services.to_u64();
                            ret_addrs.push(CrawledNode::NewNode(CrawlInfo {
                                node_info: new_info,
                                age: 0,
                            }));
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
                            Err(..) => Err("IP type address couldn't be turned into SocketAddr"),
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
                                Base32Unpadded::encode_string(&to_enc).trim_matches(char::from(0)),
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
                                ret_addrs.push(CrawledNode::NewNode(CrawlInfo {
                                    node_info: new_info,
                                    age: 0,
                                }));
                            }
                        }
                        Err(e) => println!("Error: {e}"),
                    }
                }
                break;
            }
            NetworkMessage::Ping(ping) => {
                protocol
                    .write(&Payload::genuine(V2Serialize(V2NetworkMessage::Pong(ping))))
                    .await
                    .unwrap();
            }
            _ => (),
        };
        write_buf.clear();
    }
    Ok(ret_addrs)
}

async fn connect_node(
    node: &NodeInfo,
    net_status: &NetStatus,
) -> Result<TcpStream, Box<dyn Error + Send + Sync>> {
    match node.addr.host {
        Host::Ipv4(ip) if net_status.ipv4 => {
            Ok(timeout(
                time::Duration::from_secs(10),
                TcpStream::connect(&SocketAddr::new(IpAddr::V4(ip), node.addr.port)),
            )
            .await??)
        }
        Host::Ipv6(ip) if net_status.ipv6 => {
            Ok(timeout(
                time::Duration::from_secs(10),
                TcpStream::connect(&SocketAddr::new(IpAddr::V6(ip), node.addr.port)),
            )
            .await??)
        }
        Host::CJDNS(ip) if net_status.cjdns => {
            Ok(timeout(
                time::Duration::from_secs(10),
                TcpStream::connect(&SocketAddr::new(IpAddr::V6(ip), node.addr.port)),
            )
            .await??)
        }
        Host::OnionV3(ref host) if net_status.onion_proxy.is_some() => {
            let proxy_addr = net_status.onion_proxy.as_ref().unwrap();
            let mut stream = timeout(
                time::Duration::from_secs(10),
                TcpStream::connect(&SocketAddr::from_str(proxy_addr).unwrap()),
            )
            .await?;
            if let Ok(mut_stream) = &mut stream {
                let cr = socks5_connect(mut_stream, host, node.addr.port).await;
                match cr {
                    Ok(_) => Ok(stream?),
                    Err(e) => Err(Box::new(std::io::Error::other(e))),
                }
            } else {
                Ok(stream?)
            }
        }
        Host::I2P(ref host) if net_status.i2p_proxy.is_some() => {
            let proxy_addr = net_status.i2p_proxy.as_ref().unwrap();
            let mut stream = timeout(
                time::Duration::from_secs(10),
                TcpStream::connect(&SocketAddr::from_str(proxy_addr).unwrap()),
            )
            .await?;
            if let Ok(mut_stream) = &mut stream {
                let cr = socks5_connect(mut_stream, host, node.addr.port).await;
                match cr {
                    Ok(_) => Ok(stream?),
                    Err(e) => Err(Box::new(std::io::Error::other(e))),
                }
            } else {
                Ok(stream?)
            }
        }
        _ => Err(Box::new(NetNotAvailableError {})),
    }
}

async fn crawl_node(node: &NodeInfo, net_status: NetStatus) -> Vec<CrawledNode> {
    let tried_timestamp = time::SystemTime::now()
        .duration_since(time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let age = tried_timestamp - node.last_tried;
    let mut ret_addrs = Vec::<CrawledNode>::new();

    println!(
        "Trying {}, current try = {}",
        &node.addr.to_string(),
        node.try_count + 1
    );

    let v2_conn_res = connect_node(node, &net_status).await;
    if let Err(v2_conn_err) = v2_conn_res {
        if v2_conn_err.is::<NetNotAvailableError>() {
            println!("Network not available for {}", &node.addr.to_string());
        } else {
            let mut node_info = node.clone();
            node_info.last_tried = tried_timestamp;
            ret_addrs.push(CrawledNode::Failed(CrawlInfo { node_info, age }));
            println!("Failed connect: {}", &node.addr.to_string());
        }
        return ret_addrs;
    }
    let mut v2_sock = v2_conn_res.unwrap();

    println!("Connected to {} for v2 crawl", &node.addr.to_string());

    match timeout(
        time::Duration::from_secs(30),
        get_node_addrs_v2(&mut v2_sock, node, &net_status, tried_timestamp, age),
    )
    .await
    {
        Ok(v1_ret) => match v1_ret {
            Ok(r) => ret_addrs.extend(r),
            Err(v2_err) => {
                if !v2_err.is::<V2ConnectError>() {
                    let mut node_info = node.clone();
                    node_info.last_tried = tried_timestamp;
                    ret_addrs.push(CrawledNode::Failed(CrawlInfo { node_info, age }));
                    println!("Failed crawl: {}, {}", &node.addr.to_string(), v2_err);
                    v2_sock.shutdown().await.unwrap();
                    return ret_addrs;
                }
            }
        },
        Err(_) => {
            println!("{} v2 connection timed out", &node.addr.to_string());
        }
    };
    v2_sock.shutdown().await.unwrap();

    if ret_addrs.len() == 0 {
        // Only timeout or V2ConnectError failures, so try v1
        let v1_conn_res = connect_node(node, &net_status).await;
        if v1_conn_res.is_err() {
            let mut node_info = node.clone();
            node_info.last_tried = tried_timestamp;
            ret_addrs.push(CrawledNode::Failed(CrawlInfo { node_info, age }));
            println!("Failed connect: {}", &node.addr.to_string());
            return ret_addrs;
        }
        let mut v1_sock = v1_conn_res.unwrap();

        println!("Connected to {} for v1 crawl", &node.addr.to_string());

        match timeout(
            time::Duration::from_secs(30),
            get_node_addrs_v1(&mut v1_sock, node, &net_status, tried_timestamp, age),
        )
        .await
        {
            Ok(v1_ret) => match v1_ret {
                Ok(r) => ret_addrs.extend(r),
                Err(v1_err) => {
                    let mut node_info = node.clone();
                    node_info.last_tried = tried_timestamp;
                    ret_addrs.push(CrawledNode::Failed(CrawlInfo { node_info, age }));
                    println!("Failed crawl: {}, {}", &node.addr.to_string(), v1_err);
                    v1_sock.shutdown().await.unwrap();
                    return ret_addrs;
                }
            },
            Err(_) => {
                println!("{} v1 connection timed out", &node.addr.to_string());
            }
        };
        v1_sock.shutdown().await.unwrap();
    }

    println!("Done {}", &node.addr.to_string());
    ret_addrs
}

fn calculate_reliability(good: bool, old_reliability: f64, age: u64, window: u64) -> f64 {
    let alpha = 1.0 - (-(age as f64) / window as f64).exp(); // 1 - e^(-delta T / tau)
    let x = if good { 1.0 } else { 0.0 };
    (alpha * x) + ((1.0 - alpha) * old_reliability) // alpha * x + (1 - alpha) * s_{t-1}
}

pub async fn crawler_thread(
    db_conn: Arc<Mutex<rusqlite::Connection>>,
    threads: usize,
    mut net_status: NetStatus,
) {
    // Check proxies
    println!("Checking onion proxy");
    {
        let mut onion_proxy_check = timeout(
            time::Duration::from_secs(10),
            TcpStream::connect(
                &SocketAddr::from_str(net_status.onion_proxy.as_ref().unwrap()).unwrap(),
            ),
        )
        .await
        .unwrap();
        if let Ok(onion_proxy_sock) = &mut onion_proxy_check {
            if socks5_connect(
                onion_proxy_sock,
                &"duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion".to_string(),
                80,
            )
            .await
            .is_err()
            {
                net_status.onion_proxy = None;
            }
            onion_proxy_check.unwrap().shutdown().await.unwrap();
        } else {
            net_status.onion_proxy = None;
        }
    }
    match net_status.onion_proxy {
        Some(..) => println!("Onion proxy good"),
        None => println!("Onion proxy bad"),
    }

    println!("Checking I2P proxy");
    {
        let mut i2p_proxy_check = timeout(
            time::Duration::from_secs(10),
            TcpStream::connect(
                &SocketAddr::from_str(net_status.i2p_proxy.as_ref().unwrap()).unwrap(),
            ),
        )
        .await
        .unwrap();
        if let Ok(i2p_proxy_sock) = &mut i2p_proxy_check {
            if socks5_connect(
                i2p_proxy_sock,
                &"gqt2klvr6r2hpdfxzt4bn2awwehsnc7l5w22fj3enbauxkhnzcoq.b32.i2p".to_string(),
                80,
            )
            .await
            .is_err()
            {
                net_status.i2p_proxy = None;
                println!("I2P proxy couldn't connect to test server");
            }
            i2p_proxy_check.unwrap().shutdown().await.unwrap();
        } else {
            println!("I2P proxy didn't connect");
            net_status.i2p_proxy = None;
        }
    }
    match net_status.i2p_proxy {
        Some(..) => println!("I2P proxy good"),
        None => println!("I2P proxy bad"),
    }

    // Semaphore to limit how many tasks are spawned
    let sem = Arc::new(Semaphore::new(threads));

    // Track which nodes a task is already crawling
    let nodes_in_flight = Arc::new(Mutex::new(HashSet::<NodeAddress>::new()));

    // Crawler loop
    loop {
        // Get nodes that were last tried more than 10 min ago, sorted oldest first
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
                    Ok(ni) => ni.ok(),
                    Err(..) => None,
                })
                .collect();
        }

        // Spawn a task to crawl each node, limited by the semaphore which uses the threads argument
        for node in nodes {
            {
                let mut in_flight = nodes_in_flight.lock().unwrap();
                if in_flight.get(&node.addr).is_some() {
                    println!(
                        "Crawl spawner: {} is already in flight",
                        &node.addr.to_string()
                    );
                    continue;
                }
                in_flight.insert(node.addr.clone());
            }

            let f_in_flight = nodes_in_flight.clone();
            let net_status_c: NetStatus = net_status.clone();
            let f_db_conn = db_conn.clone();
            let sem_clone = Arc::clone(&sem);
            println!(
                "Crawl spawner - {}: waiting for semaphore, {} permits available",
                &node.addr.to_string(),
                sem_clone.available_permits()
            );
            let permit = sem_clone.acquire_owned().await;
            println!(
                "Crawl spawner - {}: acquired semaphore",
                &node.addr.to_string()
            );

            // Crawler task
            tokio::spawn(async move {
                let _permit = permit;
                let addrs = crawl_node(&node, net_status_c).await;

                /*
                println!(
                    "Crawler thread - {}: Waiting for database",
                    &node.addr.to_string()
                );
                */
                let locked_db_conn = f_db_conn.lock().unwrap();
                //println!("Crawler thread - {}: Have database", &node.addr.to_string());
                locked_db_conn.execute("BEGIN TRANSACTION", []).unwrap();
                for crawled in addrs {
                    match crawled {
                        CrawledNode::Failed(info) => {
                            locked_db_conn
                                .execute(
                                    "
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
                                        calculate_reliability(
                                            false,
                                            info.node_info.reliability_2h,
                                            info.age,
                                            3600 * 2
                                        ),
                                        calculate_reliability(
                                            false,
                                            info.node_info.reliability_8h,
                                            info.age,
                                            3600 * 8
                                        ),
                                        calculate_reliability(
                                            false,
                                            info.node_info.reliability_1d,
                                            info.age,
                                            3600 * 24
                                        ),
                                        calculate_reliability(
                                            false,
                                            info.node_info.reliability_1w,
                                            info.age,
                                            3600 * 24 * 7
                                        ),
                                        calculate_reliability(
                                            false,
                                            info.node_info.reliability_1m,
                                            info.age,
                                            3600 * 24 * 30
                                        ),
                                        info.node_info.addr.to_string(),
                                    ],
                                )
                                .unwrap();
                        }
                        CrawledNode::UpdatedInfo(info) => {
                            locked_db_conn
                                .execute(
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
                                        calculate_reliability(
                                            true,
                                            info.node_info.reliability_2h,
                                            info.age,
                                            3600 * 2
                                        ),
                                        calculate_reliability(
                                            true,
                                            info.node_info.reliability_8h,
                                            info.age,
                                            3600 * 8
                                        ),
                                        calculate_reliability(
                                            true,
                                            info.node_info.reliability_1d,
                                            info.age,
                                            3600 * 24
                                        ),
                                        calculate_reliability(
                                            true,
                                            info.node_info.reliability_1w,
                                            info.age,
                                            3600 * 24 * 7
                                        ),
                                        calculate_reliability(
                                            true,
                                            info.node_info.reliability_1m,
                                            info.age,
                                            3600 * 24 * 30
                                        ),
                                        info.node_info.addr.to_string(),
                                    ],
                                )
                                .unwrap();
                        }
                        CrawledNode::NewNode(info) => {
                            locked_db_conn.execute(
                                "INSERT OR IGNORE INTO nodes VALUES(?, 0, 0, '', ?, 0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0)",
                                params![&info.node_info.addr.to_string(), info.node_info.services.to_be_bytes()]
                            ).unwrap();
                        }
                    }
                }
                locked_db_conn.execute("COMMIT TRANSACTION", []).unwrap();
                /*
                println!(
                    "Crawler thread - {}: Done with database",
                    &node.addr.to_string()
                );
                */

                {
                    f_in_flight.lock().unwrap().remove(&node.addr);
                }
            });
        }
    }
}
