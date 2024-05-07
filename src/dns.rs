use crate::common::{is_good, BindProtocol, Host, NodeInfo};
use crate::dnssec::{parse_dns_keys_dir, DnsSigningKey, RecordsToSign};

use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::{Arc, Mutex, RwLock},
    time,
};

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
        dnssec::{Nsec, RtypeBitmap, RtypeBitmapBuilder},
        rfc1035::{Ns, Soa, A},
    },
    sign::{key::SigningKey, records::FamilyName},
};
use rand::{seq::SliceRandom, thread_rng};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter},
    net::{TcpListener, UdpSocket},
    time::timeout,
};

#[derive(Clone)]
struct CachedAddrs {
    ipv4: Vec<Ipv4Addr>,
    ipv6: Vec<Ipv6Addr>,
    timestamp: time::Instant,
}

impl CachedAddrs {
    fn new() -> CachedAddrs {
        CachedAddrs {
            ipv4: vec![],
            ipv6: vec![],
            timestamp: time::Instant::now(),
        }
    }
}

struct SeederInfo {
    // Static, setup on init and never changes
    seed_domain: Name<Vec<u8>>,
    seed_apex: FamilyName<Name<Vec<u8>>>,
    server_name: Name<Vec<u8>>,
    dnskeys: HashMap<(u16, SecAlg), DnsSigningKey>,
    names_served: Vec<Name<Vec<u8>>>,
    soa_record: Record<Name<Vec<u8>>, Soa<Name<Vec<u8>>>>,
    chain: Network,

    // Consts, but can't make them compile time.
    allowed_filters: HashMap<String, ServiceFlags>,
    apex_rtypes: RtypeBitmap<Vec<u8>>,
    other_rtypes: RtypeBitmap<Vec<u8>>,
}

impl SeederInfo {
    fn new(
        seed_name: &str,
        server_name: &str,
        soa_rname: &str,
        dnskeys_dir: Option<String>,
        chain: Network,
    ) -> SeederInfo {
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
                ServiceFlags::NETWORK_LIMITED
                    | ServiceFlags::WITNESS
                    | ServiceFlags::COMPACT_FILTERS,
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
        let dnskeys = parse_dns_keys_dir(dnskeys_dir, seed_name);

        // Make static SOA record
        let soa_record = Record::new(
            seed_domain_dname.clone(),
            Class::IN,
            Ttl::from_secs(900),
            Soa::new(
                seed_domain_dname.clone(),
                soa_rname_dname,
                Serial(1),
                Ttl::from_secs(3600),
                Ttl::from_secs(3600),
                Ttl::from_secs(86400),
                Ttl::from_secs(60),
            ),
        );

        SeederInfo {
            seed_domain: seed_domain_dname,
            seed_apex,
            server_name: server_dname,
            dnskeys,
            names_served,
            soa_record,
            chain,
            allowed_filters,
            apex_rtypes: apex_rtype_builder.finalize(),
            other_rtypes: other_rtype_builder.finalize(),
        }
    }

    fn get_soa(&self) -> Record<Name<Vec<u8>>, Soa<Name<Vec<u8>>>> {
        self.soa_record.clone()
    }
}

async fn build_dns_failed(
    req: &Message<[u8]>,
    code: Rcode,
    query: &Option<Question<ParsedName<&[u8]>>>,
    seeder: Arc<SeederInfo>,
) -> Result<Message<Vec<u8>>, String> {
    let res_builder = MessageBuilder::new_vec();
    match res_builder.start_answer(req, code) {
        Ok(res) => {
            // No answer, skip directly to authority
            let mut auth = res.authority();

            // Add SOA record for only NOERROR and NXDOMAIN
            if query.is_some() && (code == Rcode::NOERROR || code == Rcode::NXDOMAIN) {
                auth.header_mut().set_aa(true);
                let mut auth_recs_sign = RecordsToSign::new();
                auth.push(seeder.get_soa()).unwrap();
                auth_recs_sign.add_soa(seeder.get_soa());

                // DNSSEC signing and NSEC records
                if req.opt().is_some()
                    && req.opt().unwrap().dnssec_ok()
                    && !seeder.dnskeys.is_empty()
                {
                    // Set NSEC records
                    let mut next_name;
                    let mut insert_apex = false;
                    match seeder
                        .names_served
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
                            seeder.names_served[0].clone(),
                            Class::IN,
                            Ttl::from_secs(60),
                            Nsec::new(seeder.names_served[1].clone(), seeder.apex_rtypes.clone()),
                        );
                        auth.push(rec.clone()).unwrap();
                        auth_recs_sign.add_nsec(rec);
                    }
                    if next_name > 1 {
                        let prev_name = next_name - 1;
                        // When next_name is out of range, it wraps around
                        if next_name >= seeder.names_served.len() {
                            next_name = 0;
                        }
                        let rec = Record::new(
                            seeder.names_served[prev_name].clone(),
                            Class::IN,
                            Ttl::from_secs(60),
                            Nsec::new(
                                seeder.names_served[next_name].clone(),
                                seeder.other_rtypes.clone(),
                            ),
                        );
                        auth.push(rec.clone()).unwrap();
                        auth_recs_sign.add_nsec(rec);
                    }

                    // Sign
                    for rrsig in auth_recs_sign.sign(&seeder.dnskeys, &seeder.seed_apex) {
                        let _ = auth.push(rrsig);
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

            Ok(addl.into_message())
        }
        Err(e) => Err(format!("Failed to build DNS no data: {}", e)),
    }
}

async fn process_dns_request(
    buf: &[u8],
    req_len: usize,
    seeder: Arc<SeederInfo>,
    cache: Arc<RwLock<HashMap<ServiceFlags, CachedAddrs>>>,
    db_conn: Arc<Mutex<rusqlite::Connection>>,
) -> Result<Vec<Message<Vec<u8>>>, String> {
    let mut ret_msgs = Vec::<Message<Vec<u8>>>::new();
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
        if let Ok(msg) = build_dns_failed(req, Rcode::SERVFAIL, &None, seeder.clone()).await {
            ret_msgs.push(msg)
        }
        return Ok(ret_msgs);
    }

    // Track records for signing
    let mut ans_recs_sign = RecordsToSign::new();

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
                if let Ok(msg) = build_dns_failed(req, Rcode::FORMERR, &None, seeder.clone()).await
                {
                    ret_msgs.push(msg);
                }
                continue;
            }
        };
        let name = question.qname();

        // Make sure we can serve this
        if !name.ends_with(&seeder.seed_domain) {
            if let Ok(msg) =
                build_dns_failed(req, Rcode::REFUSED, &Some(question), seeder.clone()).await
            {
                ret_msgs.push(msg);
            }
            continue;
        }

        // Check for xNNN.<name> service flag filter
        let mut filter: ServiceFlags = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
        if name.label_count() != seeder.seed_domain.label_count() {
            if name.label_count() != seeder.seed_domain.label_count() + 1 {
                if let Ok(msg) =
                    build_dns_failed(req, Rcode::NXDOMAIN, &Some(question), seeder.clone()).await
                {
                    ret_msgs.push(msg);
                }
                continue;
            }
            let filter_label = name.first().to_string();
            let this_filter = seeder.allowed_filters.get(&filter_label);
            if this_filter.is_none() {
                if let Ok(msg) =
                    build_dns_failed(req, Rcode::NXDOMAIN, &Some(question), seeder.clone()).await
                {
                    ret_msgs.push(msg);
                }
                continue;
            }
            filter = *this_filter.unwrap();
        }

        // Check supported class
        match question.qclass() {
            Class::IN => (),
            _ => {
                if let Ok(msg) =
                    build_dns_failed(req, Rcode::NOTIMP, &Some(question), seeder.clone()).await
                {
                    ret_msgs.push(msg);
                }
                continue;
            }
        };

        // Only return these for the apex domain
        if name.eq(&seeder.seed_domain) {
            // Handle SOA separately
            if question.qtype() == Rtype::SOA {
                res.push(seeder.get_soa()).unwrap();
                ans_recs_sign.add_soa(seeder.get_soa());
                continue;
            };

            // Handle NS separately
            if question.qtype() == Rtype::NS {
                let rec = Record::new(
                    name.to_name::<Vec<u8>>(),
                    Class::IN,
                    Ttl::from_secs(86400),
                    Ns::new(seeder.server_name.clone()),
                );
                res.push(rec.clone()).unwrap();
                ans_recs_sign.add_ns(rec);
                continue;
            };

            // Handle DNSKEY separately
            if question.qtype() == Rtype::DNSKEY {
                for dnskey in seeder.dnskeys.values() {
                    let rec = Record::new(
                        name.to_name::<Vec<u8>>(),
                        Class::IN,
                        Ttl::from_secs(3600),
                        dnskey.dnskey().unwrap(),
                    );
                    let _ = res.push(rec.clone());
                    ans_recs_sign.add_dnskey(rec);
                }
                continue;
            }
        }

        // Check supported record type
        match question.qtype() {
            Rtype::A => (),
            Rtype::AAAA => (),
            _ => {
                if let Ok(msg) =
                    build_dns_failed(req, Rcode::NOERROR, &Some(question), seeder.clone()).await
                {
                    ret_msgs.push(msg);
                }
                continue;
            }
        };

        // Read from cache
        let mut read_addrs: Option<CachedAddrs>;
        {
            let cache_read = cache.read().unwrap();
            read_addrs = cache_read.get(&filter).cloned();
        }

        // If cache for this filter was empty or expired, refresh it
        if read_addrs.is_none()
            || read_addrs
                .as_ref()
                .is_some_and(|c| c.timestamp.elapsed() > time::Duration::from_secs(60 * 10))
        {
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
                            if !is_good(&nni, &seeder.chain)
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
            {
                let mut cache_write = cache.write().unwrap();
                cache_write.insert(filter, new_cache.clone());
            }
            let _ = read_addrs.insert(new_cache);
        };
        let mut addrs = read_addrs.unwrap();

        // Shuffle addresses before returning them
        let mut rng = thread_rng();
        addrs.ipv4.shuffle(&mut rng);
        addrs.ipv6.shuffle(&mut rng);

        match question.qtype() {
            Rtype::A => {
                for (i, node) in addrs.ipv4.iter().enumerate() {
                    if i >= 20 {
                        break;
                    }
                    let rec = Record::new(
                        name.to_name::<Vec<u8>>(),
                        Class::IN,
                        Ttl::from_secs(60),
                        A::new(*node),
                    );
                    res.push(rec.clone()).unwrap();
                    ans_recs_sign.add_a(rec);
                }
            }
            Rtype::AAAA => {
                for (i, node) in addrs.ipv6.iter().enumerate() {
                    if i >= 20 {
                        break;
                    }
                    let rec = Record::new(
                        name.to_name::<Vec<u8>>(),
                        Class::IN,
                        Ttl::from_secs(60),
                        Aaaa::new(*node),
                    );
                    res.push(rec.clone()).unwrap();
                    ans_recs_sign.add_aaaa(rec);
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
        for rrsig in ans_recs_sign.sign(&seeder.dnskeys, &seeder.seed_apex) {
            let _ = res.push(rrsig);
        }
    }

    // Advance to authority section
    let mut auth = res.authority();

    // Add SOA to authority section if there are no answers
    if auth.counts().ancount() == 0 {
        let mut auth_recs_sign = RecordsToSign::new();
        auth.push(seeder.get_soa()).unwrap();
        auth_recs_sign.add_soa(seeder.get_soa());

        if req.opt().is_some() && req.opt().unwrap().dnssec_ok() && !seeder.dnskeys.is_empty() {
            // Sign it
            for rrsig in auth_recs_sign.sign(&seeder.dnskeys, &seeder.seed_apex) {
                let _ = auth.push(rrsig);
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

    ret_msgs.push(addl.into_message());
    Ok(ret_msgs)
}

async fn dns_socket_task(
    proto: BindProtocol,
    bind: SocketAddr,
    seeder: Arc<SeederInfo>,
    cache: Arc<RwLock<HashMap<ServiceFlags, CachedAddrs>>>,
    db_conn: Arc<Mutex<rusqlite::Connection>>,
) {
    if proto == BindProtocol::Udp {
        // Bind UDP socket
        let udp_sock = Arc::new(UdpSocket::bind(bind).await.unwrap());
        println!("Bound UDP socket {}", udp_sock.local_addr().unwrap());

        // Main loop
        loop {
            let mut buf = [0_u8; 1500];
            let (req_len, from) = udp_sock.recv_from(&mut buf).await.unwrap();

            let udp_sock_clone = udp_sock.clone();
            let seeder_clone = seeder.clone();
            let cache_clone = cache.clone();
            let db_conn_clone = db_conn.clone();
            tokio::spawn(async move {
                match process_dns_request(
                    &buf,
                    req_len,
                    seeder_clone.clone(),
                    cache_clone.clone(),
                    db_conn_clone.clone(),
                )
                .await
                {
                    Ok(msgs) => {
                        // Send each message individually
                        for msg in msgs {
                            let _ = udp_sock_clone.send_to(msg.as_slice(), from).await;
                        }
                    }
                    Err(e) => println!("{}", e),
                }
            });
        }
    } else if proto == BindProtocol::Tcp {
        // Bind TCP Socket
        let tcp_sock = TcpListener::bind(bind).await.unwrap();
        println!("Bound TCP socket {}", tcp_sock.local_addr().unwrap());

        // Main loop
        loop {
            let (mut tcp_stream, _from) = tcp_sock.accept().await.unwrap();

            let seeder_clone = seeder.clone();
            let cache_clone = cache.clone();
            let db_conn_clone = db_conn.clone();
            tokio::spawn(async move {
                let (mut read_sock, mut write_sock) = tcp_stream.split();
                let mut reader = BufReader::new(&mut read_sock);
                let mut writer = BufWriter::new(&mut write_sock);

                // Loop to handle all possible requests
                loop {
                    // If we either get EOF, or it's been 2 minutes without data, exit
                    let req_len;
                    match timeout(time::Duration::from_secs(120), reader.read_u16()).await {
                        Ok(rb) => match rb {
                            Ok(r) => req_len = r,
                            Err(_) => break,
                        },
                        Err(_) => break,
                    }
                    let mut req = vec![0_u8; req_len as usize];
                    reader.read_exact(&mut req).await.unwrap();

                    match process_dns_request(
                        req.as_slice(),
                        req_len.into(),
                        seeder_clone.clone(),
                        cache_clone.clone(),
                        db_conn_clone.clone(),
                    )
                    .await
                    {
                        Ok(msgs) => {
                            // Send each message individually
                            for msg in msgs {
                                writer
                                    .write_u16(msg.as_octets().len() as u16)
                                    .await
                                    .unwrap();
                                writer.write_all(msg.as_slice()).await.unwrap();
                            }
                            writer.flush().await.unwrap();
                        }
                        Err(e) => println!("{}", e),
                    }
                }
            });
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn dns_thread(
    mut binds: Vec<(BindProtocol, SocketAddr)>,
    db_conn: Arc<Mutex<rusqlite::Connection>>,
    seed_domain: &str,
    server_name: &str,
    soa_rname: &str,
    chain: &Network,
    dnssec_keys: Option<String>,
) {
    #[allow(clippy::single_char_pattern)]
    let cache = Arc::new(RwLock::new(HashMap::<ServiceFlags, CachedAddrs>::new()));

    // Setup seeder info
    let seeder = Arc::new(SeederInfo::new(
        seed_domain,
        server_name,
        soa_rname,
        dnssec_keys,
        *chain,
    ));

    while binds.len() > 1 {
        // Start a task for each socket
        let (proto, bind) = binds.pop().unwrap();
        let seeder_clone = seeder.clone();
        let cache_clone = cache.clone();
        let db_conn_clone = db_conn.clone();
        tokio::spawn(async move {
            dns_socket_task(proto, bind, seeder_clone, cache_clone, db_conn_clone).await;
        });
    }

    // Use this task for the last bind
    let (proto, bind) = binds.pop().unwrap();
    dns_socket_task(proto, bind, seeder, cache, db_conn).await;
}
