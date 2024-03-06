#![feature(ip)]

use clap::Parser;
use std::net::{IpAddr, SocketAddr};
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

enum Network {
    IPv4,
    IPv6,
    OnionV3,
    I2P,
    CJDNS,
}

enum Host {
    Ip(IpAddr),
    Host(String),
}

struct NodeAddress {
    host: Host,
    port: u16,
    net: Network,
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
            return Ok(NodeAddress {
                host: Host::Ip(ip),
                port: parsed_addr.port(),
                net: Network::IPv4,
            });
        }
        assert!(ip.is_ipv6());
        if !ip.is_global() {
            // Check for CJDNS in fc00::/8
            if let IpAddr::V6(ip6) = ip {
                if matches!(ip6.octets(), [0xfc, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _]) {
                    return Ok(NodeAddress {
                        host: Host::Ip(ip),
                        port: parsed_addr.port(),
                        net: Network::CJDNS,
                    });
                }
            }
            return Err("IPv6 addresses must be globally accessible or CJDNS");
        }
        return Ok(NodeAddress {
            host: Host::Ip(ip),
            port: parsed_addr.port(),
            net: Network::IPv6,
        });
    }
    let sp: Vec<&str> = addr.split(":").collect();
    if sp.len() != 2 {
        return Err("Invalid address, not IPv6 and multiple colons or colon not found");
    }
    let host = &sp[0];
    let port = sp[1].parse::<u16>().unwrap();
    if host.len() == 62 && host.ends_with(".onion") {
        return Ok(NodeAddress{
            host: Host::Host(host.to_string()),
            port: port,
            net: Network::OnionV3,
        });
    }
    if host.len() == 60 && host.ends_with(".b32.i2p") {
        return Ok(NodeAddress{
            host: Host::Host(host.to_string()),
            port: port,
            net: Network::I2P,
        });
    }
    return Err("Invalid address");
}

fn crawl_node(db_conn: &rusqlite::Connection, addr: String) {
    let node_addr = parse_address(addr).unwrap();
    let netname = match node_addr.net {
        Network::IPv4 => "ipv4",
        Network::IPv6 => "ipv6",
        Network::OnionV3 => "onionv3",
        Network::I2P => "i2p",
        Network::CJDNS => "cjdns",
    };
    let hostname = match node_addr.host {
        Host::Ip(ip) => ip.to_string(),
        Host::Host(host) => host,
    };
    println!("{} {} {}", hostname, node_addr.port, netname);
    /*
    let node = connect_node(addr).unwrap();
    let new_addrs = node.get_addrs();
    let mut new_node_stmt = db_conn.prepare("INSERT OR IGNORE INTO nodes VALUES(?, NULL, NULL, NULL, NULL, NULL)").unwrap();
    for na in new_addrs {
        new_node_stmt.([arg]).unwrap();
    }
    */
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
