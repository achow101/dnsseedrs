use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

use bitcoin::{network::Network, p2p::ServiceFlags};

#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Host {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    CJDNS(Ipv6Addr),
    OnionV3(String),
    I2P(String),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct NodeAddress {
    pub host: Host,
    pub port: u16,
}

impl std::fmt::Display for NodeAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.host {
            Host::Ipv4(ip) => write!(f, "{}:{}", ip, self.port),
            Host::Ipv6(ip) | Host::CJDNS(ip) => write!(f, "[{}]:{}", ip, self.port),
            Host::OnionV3(s) | Host::I2P(s) => write!(f, "{}:{}", s, self.port),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub addr: NodeAddress,
    pub last_tried: u64,
    pub last_seen: u64,
    pub user_agent: String,
    pub services: u64,
    pub starting_height: i32,
    pub protocol_version: u32,
    pub try_count: i64,
    pub reliability_2h: f64,
    pub reliability_8h: f64,
    pub reliability_1d: f64,
    pub reliability_1w: f64,
    pub reliability_1m: f64,
}

impl NodeInfo {
    pub fn new(addr: String) -> Result<NodeInfo, String> {
        Self::construct(
            addr,
            0,
            0,
            "".to_string(),
            0,
            0,
            0,
            0,
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn construct(
        addr_str: String,
        last_tried: u64,
        last_seen: u64,
        user_agent: String,
        services: u64,
        starting_height: i32,
        protocol_version: u32,
        try_count: i64,
        reliability_2h: f64,
        reliability_8h: f64,
        reliability_1d: f64,
        reliability_1w: f64,
        reliability_1m: f64,
    ) -> Result<NodeInfo, String> {
        match parse_address(&addr_str) {
            Ok(a) => Ok(NodeInfo {
                addr: a,
                last_tried,
                last_seen,
                user_agent,
                services,
                starting_height,
                protocol_version,
                try_count,
                reliability_2h,
                reliability_8h,
                reliability_1d,
                reliability_1w,
                reliability_1m,
            }),
            Err(e) => Err(e.to_string()),
        }
    }
}

fn parse_address(addr: &str) -> Result<NodeAddress, &'static str> {
    let addr_parse_res = SocketAddr::from_str(addr);
    if addr_parse_res.is_ok() {
        let parsed_addr = addr_parse_res.unwrap();
        let ip = parsed_addr.ip().to_canonical();
        if let IpAddr::V4(ip4) = ip {
            // Similar to is_global(), but not unstable only feature
            if ip4.octets()[0] == 0
                || ip4.is_private()
                || ip4.is_loopback()
                || ip4.is_link_local()
                || (ip4.octets()[0] == 192 && ip4.octets()[1] == 0 && ip4.octets()[2] == 0)
                || ip4.is_documentation()
                || ip4.is_broadcast()
            {
                return Err("IPv4 addresses must be globally accessible");
            }
            return Ok(NodeAddress {
                host: Host::Ipv4(ip4),
                port: parsed_addr.port(),
            });
        }
        assert!(ip.is_ipv6());
        if let IpAddr::V6(ip6) = ip {
            // Similar to is_global(), but not unstable only feature
            if ip6.is_unspecified()
                || matches!(ip6.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
                || matches!(ip6.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
                || matches!(ip6.segments(), [0x100, 0, 0, 0, _, _, _, _])
                || (matches!(ip6.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
                    && !(u128::from_be_bytes(ip6.octets())
                        == 0x2001_0001_0000_0000_0000_0000_0000_0001
                        || u128::from_be_bytes(ip6.octets())
                            == 0x2001_0001_0000_0000_0000_0000_0000_0002
                        || matches!(ip6.segments(), [0x2001, 3, _, _, _, _, _, _])
                        || matches!(ip6.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
                        || matches!(ip6.segments(), [0x2001, b, _, _, _, _, _, _] if (0x20..=0x2F).contains(&b))))
            {
                // Check for CJDNS in fc00::/8
                if matches!(
                    ip6.octets(),
                    [0xfc, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _]
                ) {
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
    let sp: Vec<&str> = addr.split(':').collect();
    if sp.len() != 2 {
        return Err("Invalid address, not IPv6 and multiple colons or colon not found");
    }
    let host = &sp[0];
    let port = sp[1].parse::<u16>().unwrap();
    if host.len() == 62 && host.ends_with(".onion") {
        return Ok(NodeAddress {
            host: Host::OnionV3(host.to_string()),
            port,
        });
    }
    if host.len() == 60 && host.ends_with(".b32.i2p") {
        return Ok(NodeAddress {
            host: Host::I2P(host.to_string()),
            port,
        });
    }
    Err("Invalid address")
}

fn default_port(chain: &Network) -> u16 {
    match chain {
        Network::Bitcoin => 8333,
        Network::Testnet => 18333,
        Network::Signet => 38333,
        Network::Regtest => 18444,
        &_ => 0,
    }
}

fn min_blocks(chain: &Network) -> i32 {
    match chain {
        Network::Bitcoin => 800000,
        Network::Testnet => 2500000,
        _ => 1,
    }
}

pub fn is_good(node: &NodeInfo, chain: &Network) -> bool {
    match node.addr.host {
        Host::I2P(..) => (),
        _ => {
            if node.addr.port != default_port(chain) {
                return false;
            }
        }
    }
    if !ServiceFlags::from(node.services).has(ServiceFlags::NETWORK) {
        return false;
    }
    if node.protocol_version < 70001 {
        return false;
    }
    if node.starting_height < min_blocks(chain) {
        return false;
    }

    if node.reliability_2h > 0.85 && node.try_count > 2 {
        return true;
    }
    if node.reliability_8h > 0.70 && node.try_count > 4 {
        return true;
    }
    if node.reliability_1d > 0.55 && node.try_count > 8 {
        return true;
    }
    if node.reliability_1w > 0.45 && node.try_count > 16 {
        return true;
    }
    if node.reliability_1m > 0.35 && node.try_count > 32 {
        return true;
    }

    false
}

#[derive(Clone)]
pub struct NetStatus {
    pub chain: Network,
    pub ipv4: bool,
    pub ipv6: bool,
    pub cjdns: bool,
    pub onion_proxy: Option<String>,
    pub i2p_proxy: Option<String>,
}
