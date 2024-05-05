use crate::common::{is_good, Host, NodeInfo};

use std::{
    collections::HashMap,
    fs::{read_dir, File},
    io::{BufRead, BufReader},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    path::Path,
    str::FromStr,
    sync::{Arc, Mutex},
    time,
};

use base64ct::{Base64, Encoding};
use bitcoin::{network::Network, p2p::ServiceFlags};
use domain::{
    base::{
        iana::{rcode::Rcode, rtype::Rtype, Class, SecAlg},
        message::Message,
        message_builder::MessageBuilder,
        name::{Name, ParsedName, RelativeName, ToName},
        record::{Record, Ttl},
        serial::Serial,
        CanonicalOrd, Question,
    },
    rdata::{
        aaaa::Aaaa,
        dnssec::{Dnskey, Ds, Nsec, RtypeBitmap, RtypeBitmapBuilder, Timestamp},
        rfc1035::{Ns, Soa, A},
    },
    sign::{
        key::SigningKey,
        records::{FamilyName, SortedRecords},
    },
};
use rand::{seq::SliceRandom, thread_rng};
use ring::{
    error::Unspecified,
    rand::SystemRandom,
    signature::{EcdsaKeyPair, Ed25519KeyPair, Signature, ECDSA_P256_SHA256_FIXED_SIGNING},
};

struct CachedAddrs {
    ipv4: Vec<Ipv4Addr>,
    ipv6: Vec<Ipv6Addr>,
    timestamp: time::Instant,
    shuffle_timestamp: time::Instant,
}

impl CachedAddrs {
    fn new() -> CachedAddrs {
        CachedAddrs {
            ipv4: vec![],
            ipv6: vec![],
            timestamp: time::Instant::now(),
            shuffle_timestamp: time::Instant::now(),
        }
    }
}

enum DnsKeyPair {
    Ecdsa(EcdsaKeyPair),
    Ed25519(Ed25519KeyPair),
}

struct DnsSigningKey {
    keypair: DnsKeyPair,
    dnskey: Dnskey<Vec<u8>>,
    rng: SystemRandom,
}

impl DnsSigningKey {
    fn new(dnskey: Dnskey<Vec<u8>>, privkey: Vec<u8>) -> Result<DnsSigningKey, String> {
        let mut pubkey_data = dnskey.clone().into_public_key();
        let rng = SystemRandom::new();
        match dnskey.algorithm() {
            SecAlg::ECDSAP256SHA256 => {
                pubkey_data.insert(0, 0x04);
                let keypair = EcdsaKeyPair::from_private_key_and_public_key(
                    &ECDSA_P256_SHA256_FIXED_SIGNING,
                    &privkey,
                    &pubkey_data,
                    &rng,
                )
                .unwrap();
                Ok(DnsSigningKey {
                    keypair: DnsKeyPair::Ecdsa(keypair),
                    dnskey,
                    rng,
                })
            }
            SecAlg::ED25519 => {
                let keypair =
                    Ed25519KeyPair::from_seed_and_public_key(&privkey, &pubkey_data).unwrap();
                Ok(DnsSigningKey {
                    keypair: DnsKeyPair::Ed25519(keypair),
                    dnskey,
                    rng,
                })
            }
            _ => Err("Unsupported dnskey algo".to_string()),
        }
    }
}

impl SigningKey for DnsSigningKey {
    type Octets = Vec<u8>;
    type Signature = Signature;
    type Error = Unspecified;

    fn dnskey(&self) -> Result<Dnskey<Self::Octets>, Self::Error> {
        Ok(self.dnskey.clone())
    }

    fn ds<N: ToName>(&self, _owner: N) -> Result<Ds<Self::Octets>, Self::Error> {
        Err(Unspecified)
    }

    fn sign(&self, msg: &[u8]) -> Result<Self::Signature, Self::Error> {
        match self.keypair {
            DnsKeyPair::Ecdsa(ref key) => key.sign(&self.rng, msg),
            DnsKeyPair::Ed25519(ref key) => Ok(key.sign(msg)),
        }
    }
}

struct SeederInfo {
    seed_domain: Name<Vec<u8>>,
    seed_apex: FamilyName<Name<Vec<u8>>>,
    server_name: Name<Vec<u8>>,
    soa_rname: Name<Vec<u8>>,
    dnskeys: HashMap<(u16, SecAlg), DnsSigningKey>,
    names_served: Vec<Name<Vec<u8>>>,

    // Basically static, setup on init and never changed
    allowed_filters: HashMap<String, ServiceFlags>,
    apex_rtypes: RtypeBitmap<Vec<u8>>,
    other_rtypes: RtypeBitmap<Vec<u8>>,
}

impl SeederInfo {
    fn new(seed_name: &str, server_name: &str, soa_rname: &str, dnskeys_dir: Option<String>) -> SeederInfo {
        // Parse the name strings
        let seed_domain_dname: Name<Vec<u8>> = Name::from_str(seed_name).unwrap();
        let seed_apex = FamilyName::new(seed_domain_dname.clone(), Class::IN);
        let server_dname: Name<Vec<u8>> = Name::from_str(server_name).unwrap();
        let soa_rname_dname: Name<Vec<u8>> = Name::from_str(soa_rname).unwrap();

        // Fixed table of allowed filters
        let allowed_filters: HashMap<String, ServiceFlags> = HashMap::from([
            ("x1".to_string(), ServiceFlags::NETWORK),
            (
                "x5".to_string(),
                ServiceFlags::NETWORK | ServiceFlags::BLOOM,
            ),
            (
                "x9".to_string(),
                ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            ),
            (
                "x49".to_string(),
                ServiceFlags::NETWORK | ServiceFlags::WITNESS | ServiceFlags::COMPACT_FILTERS,
            ),
            (
                "x809".to_string(),
                ServiceFlags::NETWORK | ServiceFlags::WITNESS | ServiceFlags::P2P_V2,
            ),
            (
                "x849".to_string(),
                ServiceFlags::NETWORK
                    | ServiceFlags::WITNESS
                    | ServiceFlags::P2P_V2
                    | ServiceFlags::COMPACT_FILTERS,
            ),
            (
                "xd".to_string(),
                ServiceFlags::NETWORK | ServiceFlags::WITNESS | ServiceFlags::BLOOM,
            ),
            ("x400".to_string(), ServiceFlags::NETWORK_LIMITED),
            (
                "x404".to_string(),
                ServiceFlags::NETWORK_LIMITED | ServiceFlags::BLOOM,
            ),
            (
                "x408".to_string(),
                ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS,
            ),
            (
                "x448".to_string(),
                ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS | ServiceFlags::COMPACT_FILTERS,
            ),
            (
                "xc08".to_string(),
                ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS | ServiceFlags::P2P_V2,
            ),
            (
                "xc48".to_string(),
                ServiceFlags::NETWORK_LIMITED
                    | ServiceFlags::WITNESS
                    | ServiceFlags::P2P_V2
                    | ServiceFlags::COMPACT_FILTERS,
            ),
            (
                "x40c".to_string(),
                ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS | ServiceFlags::BLOOM,
            ),
        ]);

        // Get vector of served domain names in canonical ordering
        let mut names_served = Vec::<Name<Vec<u8>>>::new();
        names_served.push(seed_domain_dname.clone());
        for n in allowed_filters.keys() {
            let sub_name: RelativeName<Vec<u8>> = RelativeName::from_str(n).unwrap();
            names_served.push(sub_name.chain(seed_domain_dname.clone()).unwrap().to_name());
        }
        names_served.sort_by(|a, b| a.canonical_cmp(b));

        // Build rtype bitmaps
        let mut apex_rtype_builder = RtypeBitmapBuilder::new_vec();
        let _ = apex_rtype_builder.add(Rtype::A);
        let _ = apex_rtype_builder.add(Rtype::AAAA);
        let _ = apex_rtype_builder.add(Rtype::NS);
        let _ = apex_rtype_builder.add(Rtype::SOA);
        let _ = apex_rtype_builder.add(Rtype::RRSIG);
        let _ = apex_rtype_builder.add(Rtype::NSEC);
        let _ = apex_rtype_builder.add(Rtype::DNSKEY);
        let mut other_rtype_builder = RtypeBitmapBuilder::new_vec();
        let _ = other_rtype_builder.add(Rtype::A);
        let _ = other_rtype_builder.add(Rtype::AAAA);
        let _ = other_rtype_builder.add(Rtype::RRSIG);
        let _ = other_rtype_builder.add(Rtype::NSEC);

        // Read the DNSSEC keys
        // dnskeys map: (flags, algo) -> keypair
        let mut dnskeys = HashMap::<(u16, SecAlg), DnsSigningKey>::new();
        if dnskeys_dir.is_some() {
            let fname_prefix = format!("K{}", seed_name);
            for entry in read_dir(Path::new(&dnskeys_dir.unwrap())).unwrap() {
                let fname = entry.as_ref().unwrap().file_name().into_string().unwrap();
                if !fname.starts_with(&fname_prefix) || !fname.ends_with(".key") {
                    continue;
                }

                // Make sure there's a corresponding private key
                let privkey_fname = entry.as_ref().unwrap().path().with_extension("private");
                if !privkey_fname.is_file() {
                    continue;
                }

                // Parse the public key file
                let pubkey_file = File::open(entry.unwrap().path()).unwrap();
                let pubkey_reader = BufReader::new(pubkey_file);
                let pubkey_line = pubkey_reader.lines().last().unwrap().unwrap();
                let pubkey_line_split: Vec<&str> = pubkey_line.splitn(7, ' ').collect();
                if !pubkey_line_split[0].eq(&format!("{}.", seed_name))
                    || !pubkey_line_split[1].eq("IN")
                    || !pubkey_line_split[2].eq("DNSKEY")
                {
                    continue;
                }
                let flags = u16::from_str(pubkey_line_split[3]).unwrap();
                let algo = SecAlg::from_int(u8::from_str(pubkey_line_split[5]).unwrap());
                let pubkey = Dnskey::<Vec<u8>>::new(
                    flags,
                    u8::from_str(pubkey_line_split[4]).unwrap(),
                    algo,
                    Base64::decode_vec(&pubkey_line_split[6].replace(' ', "")).unwrap(),
                )
                .unwrap();

                // Parse the private key file
                let privkey_file = File::open(privkey_fname).unwrap();
                let privkey_reader = BufReader::new(privkey_file);
                let mut lines = privkey_reader.lines();
                let mut line = lines.next().unwrap().unwrap();
                if !line.eq("Private-key-format: v1.3") {
                    continue;
                }
                line = lines.next().unwrap().unwrap();
                let priv_algo =
                    SecAlg::from_int(u8::from_str(line.split(' ').nth(1).unwrap()).unwrap());
                if algo != priv_algo {
                    continue;
                }
                line = lines.next().unwrap().unwrap();
                let privkey = Base64::decode_vec(line.split(' ').nth(1).unwrap()).unwrap();

                let dns_sign_key = DnsSigningKey::new(pubkey, privkey);
                if dns_sign_key.is_err() {
                    continue;
                }
                dnskeys.insert((flags, algo), dns_sign_key.unwrap());
            }
        }

        SeederInfo{
            seed_domain: seed_domain_dname,
            seed_apex: seed_apex,
            server_name: server_dname,
            soa_rname: soa_rname_dname,
            dnskeys: dnskeys,
            names_served: names_served,
            allowed_filters: allowed_filters,
            apex_rtypes: apex_rtype_builder.finalize(),
            other_rtypes: other_rtype_builder.finalize(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn dns_thread(
    bind_addr: &str,
    bind_port: u16,
    db_conn: Arc<Mutex<rusqlite::Connection>>,
    seed_domain: &str,
    server_name: &str,
    soa_rname: &str,
    chain: &Network,
    dnssec_keys: Option<String>,
) {
    #[allow(clippy::single_char_pattern)]
    let mut cache = HashMap::<ServiceFlags, CachedAddrs>::new();

    // Setup seeder info
    let seeder = SeederInfo::new(seed_domain, server_name, soa_rname, dnssec_keys);

    // Bind socket
    let sock = UdpSocket::bind((bind_addr, bind_port)).unwrap();
    println!("Bound socket");

    // Closure for handling failures
    let send_dns_failed = |req: &Message<[u8]>,
                           code: Rcode,
                           from: &SocketAddr,
                           query: &Option<Question<ParsedName<&[u8]>>>| {
        let res_builder = MessageBuilder::new_vec();
        match res_builder.start_answer(req, code) {
            Ok(res) => {
                // No answer, skip directly to authority
                let mut auth = res.authority();

                // Add SOA record for only NOERROR and NXDOMAIN
                if query.is_some() && (code == Rcode::NOERROR || code == Rcode::NXDOMAIN) {
                    let mut soa_auth_recs_sign =
                        SortedRecords::<&Name<Vec<u8>>, Soa<&Name<Vec<u8>>>>::new();
                    let rec = Record::new(
                        &seeder.server_name,
                        Class::IN,
                        Ttl::from_secs(900),
                        Soa::new(
                            &seeder.server_name,
                            &seeder.soa_rname,
                            Serial(1),
                            Ttl::from_secs(3600),
                            Ttl::from_secs(3600),
                            Ttl::from_secs(86400),
                            Ttl::from_secs(60),
                        ),
                    );
                    auth.push(rec.clone()).unwrap();
                    let _ = soa_auth_recs_sign.insert(rec);

                    // DNSSEC signing and NSEC records
                    if req.opt().is_some() && req.opt().unwrap().dnssec_ok() && !seeder.dnskeys.is_empty()
                    {
                        let incep_ts =
                            Timestamp::from(Timestamp::now().into_int().overflowing_sub(43200).0);
                        let exp_ts = Timestamp::from(
                            Timestamp::now().into_int().overflowing_add(86400 * 7).0,
                        );

                        // Sign the SOA
                        for algo in [SecAlg::ECDSAP256SHA256, SecAlg::ED25519] {
                            let key = seeder.dnskeys.get(&(256, algo));
                            if key.is_none() {
                                continue;
                            }
                            for rrsig in soa_auth_recs_sign
                                .sign::<Signature, &DnsSigningKey, Name<Vec<u8>>>(
                                    &seeder.seed_apex,
                                    exp_ts,
                                    incep_ts,
                                    key.unwrap(),
                                )
                                .unwrap()
                            {
                                let _ = auth.push(rrsig);
                            }
                        }

                        // Set NSEC records
                        let mut nsec_auth_recs_sign =
                            SortedRecords::<&Name<Vec<u8>>, Nsec<Vec<u8>, &Name<Vec<u8>>>>::new();
                        let mut next_name;
                        let mut insert_apex = false;
                        match seeder.names_served
                            .binary_search_by(|a| a.canonical_cmp(&query.unwrap().qname()))
                        {
                            Ok(p) => {
                                next_name = p + 1;
                            }
                            Err(p) => {
                                next_name = p;
                                // Insert apex if there is no exact match
                                insert_apex = true
                            }
                        };
                        // Insert NSEC for apex
                        if insert_apex || next_name == 1 {
                            let rec = Record::new(
                                &seeder.names_served[0],
                                Class::IN,
                                Ttl::from_secs(60),
                                Nsec::new(&seeder.names_served[1], seeder.apex_rtypes.clone()),
                            );
                            auth.push(rec.clone()).unwrap();
                            let _ = nsec_auth_recs_sign.insert(rec);
                        }
                        if next_name > 1 {
                            let prev_name = next_name - 1;
                            // When next_name is out of range, it wraps around
                            if next_name >= seeder.names_served.len() {
                                next_name = 0;
                            }
                            let rec = Record::new(
                                &seeder.names_served[prev_name],
                                Class::IN,
                                Ttl::from_secs(60),
                                Nsec::new(&seeder.names_served[next_name], seeder.other_rtypes.clone()),
                            );
                            auth.push(rec.clone()).unwrap();
                            let _ = nsec_auth_recs_sign.insert(rec);
                        }

                        // Sign the NSECs
                        for algo in [SecAlg::ECDSAP256SHA256, SecAlg::ED25519] {
                            let key = seeder.dnskeys.get(&(256, algo));
                            if key.is_none() {
                                continue;
                            }
                            for rrsig in nsec_auth_recs_sign
                                .sign::<Signature, &DnsSigningKey, Name<Vec<u8>>>(
                                    &seeder.seed_apex,
                                    exp_ts,
                                    incep_ts,
                                    key.unwrap(),
                                )
                                .unwrap()
                            {
                                let _ = auth.push(rrsig);
                            }
                        }
                    }
                }

                // Additional section
                let mut addl = auth.additional();
                if req.opt().is_some() {
                    addl.opt(|opt| {
                        opt.set_rcode(code.into());
                        if req.opt().unwrap().dnssec_ok() {
                            opt.set_dnssec_ok(true);
                        }
                        Ok(())
                    })
                    .unwrap();
                }

                // Send
                let _ = sock.send_to(addl.into_message().as_slice(), from);
            }
            Err(e) => {
                println!("Failed to send DNS no data: {}", e);
            }
        }
    };

    // Main loop
    loop {
        let ret: Result<(), String> = (|| -> Result<(), String> {
            // Handle queries
            let mut buf = [0_u8; 1500];
            let (req_len, from) = sock.recv_from(&mut buf).unwrap();

            let req = match Message::from_slice(&buf[..req_len]) {
                Ok(r) => r,
                Err(e) => {
                    return Err(format!("E1 {}", e));
                }
            };

            let req_header = req.header();
            if req_header.qr() {
                // Ignore non-queries
                return Err("Ignored non-query".to_string());
            }
            if req_header.tc() {
                send_dns_failed(req, Rcode::SERVFAIL, &from, &None);
                return Err("Received truncated, unsupported".to_string());
            }

            // Track records for signing
            let mut soa_ans_recs_sign =
                SortedRecords::<ParsedName<&[u8]>, Soa<&Name<Vec<u8>>>>::new();
            let mut a_ans_recs_sign = SortedRecords::<ParsedName<&[u8]>, A>::new();
            let mut aaaa_ans_recs_sign = SortedRecords::<ParsedName<&[u8]>, Aaaa>::new();
            let mut ns_ans_recs_sign =
                SortedRecords::<ParsedName<&[u8]>, Ns<&Name<Vec<u8>>>>::new();
            let mut dnskey_ans_recs_sign =
                SortedRecords::<ParsedName<&[u8]>, Dnskey<Vec<u8>>>::new();

            // Answer the questions
            let mut res_builder = MessageBuilder::new_vec();
            res_builder.header_mut().set_aa(true);
            let mut res = match res_builder.start_answer(req, Rcode::NOERROR) {
                Ok(r) => r,
                Err(e) => {
                    return Err(format!("E3 {}", e));
                }
            };
            for q_r in req.question() {
                let question = match q_r {
                    Ok(q) => q,
                    Err(..) => {
                        send_dns_failed(req, Rcode::FORMERR, &from, &None);
                        continue;
                    }
                };
                let name = question.qname();

                // Make sure we can serve this
                if !name.ends_with(&seeder.seed_domain) {
                    send_dns_failed(req, Rcode::REFUSED, &from, &Some(question));
                    continue;
                }

                // Check for xNNN.<name> service flag filter
                let mut filter: ServiceFlags = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
                if name.label_count() != seeder.seed_domain.label_count() {
                    if name.label_count() != seeder.seed_domain.label_count() + 1 {
                        send_dns_failed(req, Rcode::NXDOMAIN, &from, &Some(question));
                        continue;
                    }
                    let filter_label = name.first().to_string();
                    let this_filter = seeder.allowed_filters.get(&filter_label);
                    if this_filter.is_none() {
                        send_dns_failed(req, Rcode::NXDOMAIN, &from, &Some(question));
                        continue;
                    }
                    filter = *this_filter.unwrap();
                }

                // Check supported class
                match question.qclass() {
                    Class::IN => (),
                    _ => {
                        send_dns_failed(req, Rcode::NOTIMP, &from, &Some(question));
                        continue;
                    }
                };

                // Only return these for the apex domain
                if name.eq(&seeder.seed_domain) {
                    // Handle SOA separately
                    if question.qtype() == Rtype::SOA {
                        let rec = Record::new(
                            *name,
                            Class::IN,
                            Ttl::from_secs(900),
                            Soa::new(
                                &seeder.server_name,
                                &seeder.soa_rname,
                                Serial(1),
                                Ttl::from_secs(3600),
                                Ttl::from_secs(3600),
                                Ttl::from_secs(86400),
                                Ttl::from_secs(60),
                            ),
                        );
                        res.push(rec.clone()).unwrap();
                        let _ = soa_ans_recs_sign.insert(rec);
                        continue;
                    };

                    // Handle NS separately
                    if question.qtype() == Rtype::NS {
                        let rec = Record::new(
                            *name,
                            Class::IN,
                            Ttl::from_secs(86400),
                            Ns::new(&seeder.server_name),
                        );
                        res.push(rec.clone()).unwrap();
                        let _ = ns_ans_recs_sign.insert(rec);
                        continue;
                    };

                    // Handle DNSKEY separately
                    if question.qtype() == Rtype::DNSKEY {
                        for dnskey in seeder.dnskeys.values() {
                            let rec = Record::new(
                                *name,
                                Class::IN,
                                Ttl::from_secs(3600),
                                dnskey.dnskey().unwrap(),
                            );
                            let _ = res.push(rec.clone());
                            let _ = dnskey_ans_recs_sign.insert(rec);
                        }
                        continue;
                    }
                }

                // Check supported record type
                match question.qtype() {
                    Rtype::A => (),
                    Rtype::AAAA => (),
                    _ => {
                        send_dns_failed(req, Rcode::NOERROR, &from, &Some(question));
                        continue;
                    }
                };

                // Check or fill cache
                let needs_refresh = match cache.get(&filter) {
                    Some(c) => c.timestamp.elapsed() > time::Duration::from_secs(60 * 10),
                    None => true,
                };
                if needs_refresh {
                    let locked_db_conn = db_conn.lock().unwrap();
                    let mut select_nodes = locked_db_conn
                        .prepare("SELECT * FROM nodes WHERE try_count > 0 ORDER BY RANDOM()")
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
                    let nodes: Vec<NodeInfo> = node_iter
                        .filter_map(|n| match n {
                            Ok(ni) => match ni {
                                Ok(nni) => {
                                    if !is_good(&nni, chain)
                                        || !ServiceFlags::from(nni.services).has(filter)
                                    {
                                        return None;
                                    }
                                    match nni.addr.host {
                                        Host::Ipv4(..) => Some(nni),
                                        Host::Ipv6(..) => Some(nni),
                                        _ => None,
                                    }
                                }
                                Err(e) => {
                                    println!("E4 {}", e);
                                    None
                                }
                            },
                            Err(e) => {
                                println!("E5 {}", e);
                                None
                            }
                        })
                        .collect();
                    let mut new_cache = CachedAddrs::new();
                    for n in nodes {
                        match n.addr.host {
                            Host::Ipv4(ip) => {
                                new_cache.ipv4.push(ip);
                            }
                            Host::Ipv6(ip) => {
                                new_cache.ipv6.push(ip);
                            }
                            _ => {
                                continue;
                            }
                        };
                    }
                    cache.insert(filter, new_cache);
                };

                let addrs: &mut CachedAddrs = cache
                    .get_mut(&filter)
                    .expect("Cache should have some entries");

                if addrs.shuffle_timestamp.elapsed() > time::Duration::from_secs(5) {
                    // Shuffle cache in place
                    let mut rng = thread_rng();
                    addrs.ipv4.shuffle(&mut rng);
                    addrs.ipv6.shuffle(&mut rng);
                    addrs.shuffle_timestamp = time::Instant::now();
                };

                match question.qtype() {
                    Rtype::A => {
                        for (i, node) in addrs.ipv4.iter().enumerate() {
                            if i >= 20 {
                                break;
                            }
                            let rec =
                                Record::new(*name, Class::IN, Ttl::from_secs(60), A::new(*node));
                            res.push(rec.clone()).unwrap();
                            let _ = a_ans_recs_sign.insert(rec);
                        }
                    }
                    Rtype::AAAA => {
                        for (i, node) in addrs.ipv6.iter().enumerate() {
                            if i >= 20 {
                                break;
                            }
                            let rec =
                                Record::new(*name, Class::IN, Ttl::from_secs(60), Aaaa::new(*node));
                            res.push(rec.clone()).unwrap();
                            let _ = aaaa_ans_recs_sign.insert(rec);
                        }
                    }
                    _ => {
                        continue;
                    }
                };
            }

            // Insert RRSIG if DNSSEC
            if req.opt().is_some()
                && req.opt().unwrap().dnssec_ok()
                && res.counts().ancount() > 0
                && !seeder.dnskeys.is_empty()
            {
                let incep_ts =
                    Timestamp::from(Timestamp::now().into_int().overflowing_sub(43200).0);
                let exp_ts =
                    Timestamp::from(Timestamp::now().into_int().overflowing_add(86400 * 7).0);

                // Sign zone records
                for algo in [SecAlg::ECDSAP256SHA256, SecAlg::ED25519] {
                    let key = seeder.dnskeys.get(&(256, algo));
                    if key.is_none() {
                        continue;
                    }
                    for rrsig in soa_ans_recs_sign
                        .sign::<Signature, &DnsSigningKey, Name<Vec<u8>>>(
                            &seeder.seed_apex,
                            exp_ts,
                            incep_ts,
                            key.unwrap(),
                        )
                        .unwrap()
                    {
                        let _ = res.push(rrsig);
                    }
                    for rrsig in a_ans_recs_sign
                        .sign::<Signature, &DnsSigningKey, Name<Vec<u8>>>(
                            &seeder.seed_apex,
                            exp_ts,
                            incep_ts,
                            key.unwrap(),
                        )
                        .unwrap()
                    {
                        let _ = res.push(rrsig);
                    }
                    for rrsig in aaaa_ans_recs_sign
                        .sign::<Signature, &DnsSigningKey, Name<Vec<u8>>>(
                            &seeder.seed_apex,
                            exp_ts,
                            incep_ts,
                            key.unwrap(),
                        )
                        .unwrap()
                    {
                        let _ = res.push(rrsig);
                    }
                    for rrsig in ns_ans_recs_sign
                        .sign::<Signature, &DnsSigningKey, Name<Vec<u8>>>(
                            &seeder.seed_apex,
                            exp_ts,
                            incep_ts,
                            key.unwrap(),
                        )
                        .unwrap()
                    {
                        let _ = res.push(rrsig);
                    }
                }

                // Sign key records
                for algo in [SecAlg::ECDSAP256SHA256, SecAlg::ED25519] {
                    let key = seeder.dnskeys.get(&(257, algo));
                    if key.is_none() {
                        continue;
                    }
                    for rrsig in dnskey_ans_recs_sign
                        .sign::<Signature, &DnsSigningKey, Name<Vec<u8>>>(
                            &seeder.seed_apex,
                            exp_ts,
                            incep_ts,
                            key.unwrap(),
                        )
                        .unwrap()
                    {
                        let _ = res.push(rrsig);
                    }
                }
            }

            // Advance to authority section
            let mut auth = res.authority();

            // Add SOA to authority section if there are no answers
            if auth.counts().ancount() == 0 {
                let mut soa_auth_recs_sign =
                    SortedRecords::<&Name<Vec<u8>>, Soa<&Name<Vec<u8>>>>::new();
                let rec = Record::new(
                    &seeder.server_name,
                    Class::IN,
                    Ttl::from_secs(900),
                    Soa::new(
                        &seeder.server_name,
                        &seeder.soa_rname,
                        Serial(1),
                        Ttl::from_secs(3600),
                        Ttl::from_secs(3600),
                        Ttl::from_secs(86400),
                        Ttl::from_secs(60),
                    ),
                );
                auth.push(rec.clone()).unwrap();
                let _ = soa_auth_recs_sign.insert(rec);

                if req.opt().is_some() && req.opt().unwrap().dnssec_ok() && !seeder.dnskeys.is_empty() {
                    // Sign it
                    let incep_ts =
                        Timestamp::from(Timestamp::now().into_int().overflowing_sub(43200).0);
                    let exp_ts =
                        Timestamp::from(Timestamp::now().into_int().overflowing_add(86400 * 7).0);
                    for algo in [SecAlg::ECDSAP256SHA256, SecAlg::ED25519] {
                        let key = seeder.dnskeys.get(&(256, algo));
                        if key.is_none() {
                            continue;
                        }
                        for rrsig in soa_auth_recs_sign
                            .sign::<Signature, &DnsSigningKey, Name<Vec<u8>>>(
                                &seeder.seed_apex,
                                exp_ts,
                                incep_ts,
                                key.unwrap(),
                            )
                            .unwrap()
                        {
                            let _ = auth.push(rrsig);
                        }
                    }
                }
            }

            // Advance to additional section
            let mut addl = auth.additional();

            // Add OPT to our response if it is there
            if req.opt().is_some() {
                addl.opt(|opt| {
                    opt.set_rcode(Rcode::NOERROR.into());
                    if req.opt().unwrap().dnssec_ok() {
                        opt.set_dnssec_ok(true);
                    }
                    Ok(())
                })
                .unwrap();
            }

            // Send response
            let _ = sock.send_to(addl.into_message().as_slice(), from);

            Ok(())
        })();

        if let Err(e) = ret {
            println!("{}", e);
        }
    }
}
