# DNSSeedrs

A Bitcoin DNS Seeder written in Rust.

## Usage

```
Usage: dnsseedrs [OPTIONS] <SERVER_NAME>

Arguments:
  <SERVER_NAME>  

Options:
  -s, --seednode <SEEDNODE>        
      --db-file <DB_FILE>          [default: sqlite.db]
      --dump-file <DUMP_FILE>      [default: seeds.txt]
      --ipv4-reachable             
      --ipv6-reachable             
  -c, --cjdns-reachable            
  -o, --onion-proxy <ONION_PROXY>  [default: 127.0.0.1:9050]
  -i, --i2p-proxy <I2P_PROXY>      [default: 127.0.0.1:4447]
  -t, --threads <THREADS>          [default: 24]
  -a, --address <ADDRESS>          [default: 0.0.0.0]
  -p, --port <PORT>                [default: 53]
      --chain <CHAIN>              [default: main]
  -h, --help                       Print help
  -V, --version                    Print version
```


## Structure

DNSSeedrs is has three componenets:

1. A crawler
2. Database dumper
3. DNS server

The main process will spawn a thread for each component. The crawler checks the
`--threads` parameter to determine how many threads it should utilize for
crawling.

### Crawler

The crawler is the most critical component as its job is to discover nodes and
compute statistics for each node. The crawler connects to nodes and requests
addresses from them. These addresses are inserted in the database to be queued
for crawling.

The crawler determines which addresses to search next by sorting by the least
recently tried. This should result in all addresses in the database being
searched periodically, and therefore the entire network crawled.

#### Supported Networks

The crawler will attempt to search on all of networks in use by Bitcoin:

1. IPv4
2. IPv6
3. Tor v3
4. I2P
5. CJDNS

Although Tor v3, I2P, and CJDNS cannot be served over DNS, they are still
crawled as those nodes may provide IPv4 and IPv6 addreses. These nodes will
additionally appear in the database dumps which can be used to update the fixed
seeds.

#### Supported Chains

The crawler supports crawling Bitcoin mainnet, testnet, and signet nodes.

#### Statistics

Reliability statistics are calculated for every node. These cover time windows
of 2 hours, 8 hours, 1 day, 1 week, and 1 month (30 days). The statistics are a
[basic exponential moving
average](https://en.wikipedia.org/wiki/Exponential_smoothing#Basic_(simple)_exponential_smoothing).
This is the same statistic used by the reference [seeder
software](https://github.com/sipa/bitcoin-seeder).

### Dumper

The database is periodically dumped to a text file that follows the same format
as the reference seeder. This file can be used for generating the fixed seeds.

### DNS Server

The DNS server thread listens on a UDP socket, and currently only supports DNS'
UDP protocol. The implementation is very basic and it pretty much only responds
to queries for A and AAAA records.

#### Served Addresses

The DNS server will select a set of 20 random "good" addresses to serve. The
"good" metric checks the following:

1. The default port is used.
2. `NODE_NETWORK` service flag is set.
3. The protocol version is at least 70001.
4. The node has at least 350,000 blocks
5. The node has one of:
  * 2 hour reliability score of 85% and at least 2 connection attempts
  * 8 hour reliability score of 70% and at least 4 connection attempts
  * 1 day reliability score of 55% and at least 8 connection attempts
  * 1 week reliability score of 45% and at least 16 connection attempts
  * 1 month reliability score of 35% and at least 32 connection attempts

#### Caching

The server caches the returned addresses for 10 minutes. If the cache is more
than 10 minutes old, the database is requeried. Otherwise, all queries in a ten
minute window will receive the same response.

#### TTL

Returned records use a TTL of 60 seconds.

## License

This software is made available under the MIT license. See LICENSE for more details.
