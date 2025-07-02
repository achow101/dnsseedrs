mod common;
mod crawl;
mod dns;
mod dnssec;
mod dump;

use crate::{
    common::{BindProtocol, NetStatus},
    crawl::crawler_thread,
    dns::dns_thread,
    dump::dumper_thread,
};

use std::{
    collections::HashSet,
    net::SocketAddr,
    path::Path,
    str::FromStr,
    sync::{Arc, Mutex},
    thread, time,
};

use bitcoin::network::Network;
use clap::Parser;
use rusqlite::params;

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

    /// protocol, IP, and port to bind to for servince DNS requests. Defaults are udp://0.0.0.0:53
    /// and tcp://0.0.0.0:53. Specify multiple times for multiple binds
    #[arg(short, long)]
    bind: Vec<String>,

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

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Pick the network
    let chain_p = Network::from_core_arg(&args.chain);
    match chain_p {
        Ok(Network::Bitcoin) | Ok(Network::Testnet) | Ok(Network::Testnet4) | Ok(Network::Signet) => (),
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

    // Parse the binds
    let mut bindset = HashSet::<(BindProtocol, SocketAddr)>::new();
    for bind in args.bind {
        let proto: BindProtocol;
        if bind.starts_with("udp://") {
            proto = BindProtocol::Udp
        } else if bind.starts_with("tcp://") {
            proto = BindProtocol::Tcp
        } else {
            println!("{} is not a valid bind", bind);
            std::process::exit(1);
        }
        let bind_addr = match SocketAddr::from_str(&bind[6..]) {
            Ok(a) => a,
            Err(_) => {
                println!("{} is not a valid bind", bind);
                std::process::exit(1);
            }
        };
        bindset.insert((proto, bind_addr));
    }
    if bindset.is_empty() {
        bindset.insert((
            BindProtocol::Udp,
            SocketAddr::from_str("0.0.0.0:53").unwrap(),
        ));
        bindset.insert((
            BindProtocol::Tcp,
            SocketAddr::from_str("0.0.0.0:53").unwrap(),
        ));
    }
    let binds = bindset.iter().cloned().collect();

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
    let t_crawl = tokio::spawn(async move {
        crawler_thread(db_conn_c, args.threads - 3, net_status_c).await;
    });

    // Start dumper thread
    let db_conn_c2 = db_conn.clone();
    let t_dump = tokio::spawn(async move {
        dumper_thread(db_conn_c2, &args.dump_file, &chain).await;
    });

    // Start DNS thread
    let db_conn_c3 = db_conn.clone();
    let t_dns = tokio::spawn(async move {
        dns_thread(
            binds,
            db_conn_c3,
            &args.seed_domain,
            &args.server_name,
            &args.soa_rname,
            &chain,
            args.dnssec_keys,
        )
        .await;
    });

    // Select on task futures as a watchdog to exit if any main thread has died
    tokio::select! {
        r = t_crawl => r.unwrap(),
        r = t_dump => r.unwrap(),
        r = t_dns => r.unwrap(),
    };
}
