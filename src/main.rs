mod common;
mod crawl;
mod dns;
mod dnssec;
mod dump;

use crate::{common::NetStatus, crawl::crawler_thread, dns::dns_thread, dump::dumper_thread};

use std::{
    path::Path,
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

#[tokio::main]
async fn main() {
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
    let t_dns = tokio::spawn(async move {
        dns_thread(
            &args.address,
            args.port,
            db_conn_c3,
            &args.seed_domain,
            &args.server_name,
            &args.soa_rname,
            &chain,
            args.dnssec_keys,
        )
        .await;
    });

    // Watchdog, exit if any main thread has died
    loop {
        if t_crawl.is_finished() || t_dump.is_finished() || t_dns.is_finished() {
            break;
        }
        thread::sleep(time::Duration::from_secs(60));
    }
}
