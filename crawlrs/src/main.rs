use clap::Parser;

#[derive(Parser)]
#[command(version, about, long_about)]
struct Args {
    #[arg(short, long)]
    seednode: Vec<String>,

    #[arg(short, long)]
    db_file: Option<String>,
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
    let node: String = select_next_node.query_row([], |r| r.get(0),).unwrap();
}
