use crate::common::{is_good, NodeInfo};

use std::{
    fs::{rename, File},
    io::{BufReader, Read, Write},
    path::Path,
    sync::{Arc, Mutex},
};

use bitcoin::network::Network;
use flate2::{write::GzEncoder, Compression};
use tokio::time::{sleep, Duration};

pub async fn dumper_thread(
    db_conn: Arc<Mutex<rusqlite::Connection>>,
    dump_file: &String,
    chain: &Network,
) {
    let mut count = 0;
    loop {
        // Sleep for 100s, then 200s, 400s, 800s, 1600s, and then 3200s forever
        sleep(Duration::from_secs(100 << count)).await;
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
                            println!("{e}");
                            None
                        }
                    },
                    Err(e) => {
                        println!("{e}");
                        None
                    }
                })
                .collect();
        }

        let txt_tmp_path = format!("{dump_file}.tmp");
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
        println!("Renaming {txt_tmp_path} to {dump_file}");
        rename(txt_tmp_path.clone(), dump_file).unwrap();

        // Compress with gz
        let gz_tmp_path = format!("{dump_file}.gz.tmp");
        println!("Writing gz to temporary file {gz_tmp_path}");
        let gz_tmp_file = File::create(&gz_tmp_path).unwrap();
        let mut enc = GzEncoder::new(gz_tmp_file, Compression::default());
        let f = File::open(dump_file).unwrap();
        let mut reader = BufReader::new(f);

        let mut buffer = [0; 1024 * 256];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break, // EOF
                Ok(count) => enc.write_all(&buffer[..count]).unwrap(),
                Err(e) => panic!("Failed to read from file: {e}"),
            }
        }
        enc.finish().unwrap();

        let gz_path = format!("{dump_file}.gz");
        let archive_path = Path::new(&gz_path);
        println!("Renaming {gz_tmp_path} to {archive_path:?}");
        rename(gz_tmp_path, archive_path).unwrap();
    }
}
