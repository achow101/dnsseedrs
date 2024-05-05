# DNSSeedrs

A Bitcoin DNS Seeder written in Rust.

## Usage

```
Usage: dnsseedrs [OPTIONS] <SEED_DOMAIN> <SERVER_NAME> <SOA_RNAME>

Arguments:
  <SEED_DOMAIN>  The domain name for which this server will return results for
  <SERVER_NAME>  The domain name of this server itself, i.e. what the NS record will point to
  <SOA_RNAME>    The exact string to place in the rname field of the SOA record

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
      --dnssec-keys <DNSSEC_KEYS>  The path to a directory containing DNSSEC keys produced by dnssec-keygen
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

A few different TTLs are in use depending on the record type.

* A, AAAA, and NSEC: 60 seconds
* SOA: 900 seconds
  * SOA also specify a minimum TTL of 60 seconds
* NS: 86400 seconds (1 day)
* DNSKEY: 3600 seconds (1 hour)

#### DNSSEC

The DNS server supports DNSSEC and will automatically respond to DNSSEC requests if DNSSEC keys
are available.

Use `--dnssec-keys <path>` to provide the path to a directory containing the keypairs.
Keys are expected to be in the format produced by BIND9's `dnssec-keygen` utility.

The currently supported signing algorithms are:
* ECDSAP256SHA256
* ED25519

The implementation of DNSSEC expects 2 keys. One key will have a flag set that indicates that it
can be used to sign other keys. This key will be used to sign the keys used by this server when it
sends a DNSKEY record, and it's hash will be signed by your parent DNS Zone's key(s). It is
referred to as the Key Signing Key (KSK). The other key, referred to as the Zone Signing Key,
will be used to sign all other records.

When multiple KSKs or ZSKs are present, all will be used to produce signatures over the Resource
Record set as applicable.

## Installation

DNSSeedrs is a single self contained binary. Simple compile it with `cargo build --release` and
the resulting `dnsseedrs` binary can be used as a simple server binary.

### Basic Invocation and DNS Setup

Since DNS uses delegation, additional configuration in the parent zone is required, and some of
this information must also be provided to DNSSeedrs. These are the required arguments of:

* `<SEED_DOMAIN>`: The domain name that will be queried. Querying this domain returns the addresses
of nodes that can be connected to. DNSSeedrs controls this Zone.
* `<SERVER_NAME>`: The domain name of this server itself. There must be a NS record in the parent
Zone which specifies this name as the nameserver for `<SEED_DOMAIN>`
* `<SOA_RNAME>`: The email address of the server administrator formatted as a domain name. The `@`
is replaced with a `.`, and all `.`s in the username of the email must be escaped (`\.`).

For example, for a seeder domain of `seeder.example.com`, hosted at `ns.example.com`, adminstered
by `john.doe@example.com`:

```
$ dnsseedrs seeder.example.com ns.example.com "john\.doe.example.com"
```

And there would additionally be the NS record:

```
seeder.example. IN NS ns.example.com.
```

### Crawler Seeding

Of course DNSSeedrs is not useful if it does not have any nodes to provide to clients. However,
it does not have it's own set of seed nodes nor does it query other DNS seeders. Rather it must
be provided some initial seed nodes to connect to. These will be inserted into the database and
will subsequently be used to bootstrap the crawler. Seednoes are specified using the `-s` or
`--seednode` options.

For example, to also use `198.51.100.1:8333`, `[2001:db8::1]:8333`, `e4tyx226c6xj3szkfwybqem6ccxwnfwkxdfjuo52vmnwpittkyeskt7k
.onion:8333`, and `np3md3om4svfflq6iolnr4hzsrbxug3wjknawc6stho4q4f7if56.b32.i2p:0` as seednodes
in the previous example:

```
$ dnsseedrs -s 198.51.100.1:8333 -s [2001:db8::1]:8333 -s e4tyx226c6xj3szkfwybqem6ccxwnfwkxdfjuo52vmnwpittkyeskt7k.onion:9333 -s np3md3om4svfflq6iolnr4hzsrbxug3wjknawc6stho4q4f7if56.b32.i2p:0 seeder.example.com ns.example.com "john\.doe.example.com"
```

### Anonymity Networks

Since Bitcoin supports the Tor, I2P, and CJDNS anonymity networks, DNSSeedrs does as well in order
to discover those nodes and present them in the database dumps to be used for fixed seed generation.

### Tor

Tor can be connected via a SOCKS5 proxy. See Tor's documentation to setup the proxy server. Once it
is available, it can be connected to by setting `--onion-proxy <proxy address>`. The default is
`127.0.0.1:9050`.

The crawler thread will automatically check to see if this proxy is available and use it if it is.
This check is only done once at startup. If the proxy goes down while DNSSeedrs is running, this
will not be detected and will negatively effect the reliability scores of Tor nodes.

### I2P

I2P can be connected via a SOCKS5 proxy. See your I2P router's documentation to setup the proxy
server. Once it is available, it can be connected to by setting `--i2p-proxy <proxy address>`.
The default is `127.0.0.1:4447`.

The crawler thread will automatically check to see if this proxy is available and use it if it is.
This check is only done once at startup. If the proxy goes down while DNSSeedrs is running, this
will not be detected and will negatively effect the reliability scores of I2P nodes.

### CJDNS

CJDNS creates a tunnel interface that uses a private range of IPv6 addresses. Other than setting it
up, there is no special configuration required.

### Network Reachability

For IPv4, IPv6, and CJDNS, no reachability tests are automatically done. As such, if these networks
are not reachable, the crawler will not know and this will negatively impact reliability scores
for any such nodes.

IPv4 and IPv6 are assumed to be reachable by default. If they are not reachable, set `--no-ipv4`
and `--no-ipv6` respectively.

CJDNS is assumed to be unreachable by default. It can be enabled by setting `-c` or `--cjdns-reachable`.

### DNSSEC Setup

DNSSEC requires additional setup in order work properly. Specifically, at least one ZSK and one KSK
must be generated and made available to DNSSeedrs. These keys are in the seeder domain name's Zone,
so should use the name of `<SEED_DOMAIN>`.

To generate `ECDSAP256SHA256` keys for `seeder.example.com`:

```
$ dnssec-keygen -a ECDSAP256SHA256 seeder.example.com
Generating key pair.
Kseeder.example.com.+013+53945
$ dnssec-keygen -a ECDSAP256SHA256 -f KSK seeder.example.com
Generating key pair.
Kseeder.example.com.+013+20806
```

`--dnssec-keys <path>` can then be used to point DNSSeedrs to the directory containing the keys.
DNSSeedrs will also only load the keys that belong to `<SEED DOMAIN>`, as indicated by their
filenames.

Additionally, a DS record committing to each KSK will need to be added to the parent Zone's DNS.
This record can be produced with:

```
$ dnssec-dsfromkey Kseeder.example.com.+013+20806.key
seeder.example.com. IN DS 20806 13 2 82197169AEEFA02FD911BEABD9356739F7F807C072493A1AEA4B90396EE29074
```

The parent Zone's DNS provider may not accept this format and instead require that the fields be
provided individually. The fields are as follows:
* `seeder.example.com.`: Name
* `IN`: Class (typically unneeded)
* `DS`: Record Type
* `20806`: Key tag
* `13`: Key Algorithm
* `2`: Digest Type
* `82197169AEEFA02FD911BEABD9356739F7F807C072493A1AEA4B90396EE29074`: Key Digest

## License

This software is made available under the MIT license. See LICENSE for more details.
