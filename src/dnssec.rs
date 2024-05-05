use std::{
    collections::HashMap,
    fs::{read_dir, File},
    io::{BufRead, BufReader},
    path::Path,
    str::FromStr,
};

use base64ct::{Base64, Encoding};
use domain::{
    base::{iana::SecAlg, name::ToName},
    rdata::dnssec::{Dnskey, Ds},
    sign::key::SigningKey,
};
use ring::{
    error::Unspecified,
    rand::SystemRandom,
    signature::{EcdsaKeyPair, Ed25519KeyPair, Signature, ECDSA_P256_SHA256_FIXED_SIGNING},
};

enum DnsKeyPair {
    Ecdsa(EcdsaKeyPair),
    Ed25519(Ed25519KeyPair),
}

pub struct DnsSigningKey {
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

pub fn parse_dns_keys_dir(
    dnskeys_dir: Option<String>,
    name: &str,
) -> HashMap<(u16, SecAlg), DnsSigningKey> {
    // dnskeys map: (flags, algo) -> keypair
    let mut dnskeys = HashMap::<(u16, SecAlg), DnsSigningKey>::new();
    if dnskeys_dir.is_some() {
        let fname_prefix = format!("K{}", name);
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
            if !pubkey_line_split[0].eq(&format!("{}.", name))
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
    dnskeys
}
