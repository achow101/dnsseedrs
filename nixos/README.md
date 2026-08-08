# NixOS Module for dnsseedrs

## Quick Start

### With Flakes

Add dnsseedrs to your flake inputs and import the module:

```nix
{
  inputs.dnsseedrs.url = "github:achow101/dnsseedrs";

  outputs = { nixpkgs, dnsseedrs, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        dnsseedrs.nixosModules.default
        {
          nixpkgs.overlays = [ dnsseedrs.overlays.default ];
          services.dnsseedrs.mainnet = {
            enable = true;
            chain = "main";
            seedDomain = "seed.example.com";
            serverName = "ns.example.com";
            soaRname = "admin.example.com";
          };
        }
      ];
    };
  };
}
```

### Without Flakes

```nix
let
  dnsseedrs = builtins.fetchGit {
    url = "https://github.com/achow101/dnsseedrs";
    ref = "main";
  };
in
{
  imports = [ "${dnsseedrs}/nixos/module.nix" ];
  nixpkgs.overlays = [
    (final: _prev: { dnsseedrs = final.callPackage "${dnsseedrs}/default.nix" { }; })
  ];

  services.dnsseedrs.mainnet = {
    enable = true;
    chain = "main";
    seedDomain = "seed.example.com";
    serverName = "ns.example.com";
    soaRname = "admin.example.com";
  };
}
```

## Multiple Instances

Each key under `services.dnsseedrs` creates an independent instance with its own
systemd service (`dnsseedrs-<name>`) and state directory (`/var/lib/dnsseedrs/<name>`).

See `example-configuration.nix` for a mainnet + signet setup.

## Module Options

| Option | Type | Default | Description |
|---|---|---|---|
| `enable` | bool | `false` | Enable this instance |
| `package` | package | `pkgs.dnsseedrs` | Package to use |
| `chain` | enum | *(required)* | `"main"`, `"test"`, `"testnet4"`, or `"signet"` |
| `seedDomain` | string | *(required)* | Domain to serve DNS results for |
| `serverName` | string | *(required)* | This server's domain (NS target) |
| `soaRname` | string | *(required)* | SOA rname field value |
| `seedNodes` | list of string | `[]` | Initial seed node addresses |
| `dbFile` | string | `"sqlite.db"` | SQLite database filename |
| `dumpFile` | string | `"seeds.txt"` | Dump file for good addresses |
| `noIpv4` | bool | `false` | Disable IPv4 crawling |
| `noIpv6` | bool | `false` | Disable IPv6 crawling |
| `cjdnsReachable` | bool | `false` | Enable CJDNS reachability |
| `onionProxy` | string or null | `null` | Tor SOCKS5 proxy address |
| `i2pProxy` | string or null | `null` | I2P SOCKS5 proxy address |
| `threads` | positive int | `24` | Crawler thread count |
| `bind` | list of string | `[]` | DNS bind addresses (e.g. `udp://0.0.0.0:53`) |
| `dnssecKeys` | path or null | `null` | DNSSEC key directory |
| `asmap` | path or null | `null` | ASMap file path |
| `extraArgs` | list of string | `[]` | Additional CLI arguments |

## CoreDNS Forwarding

Bind dnsseedrs to a non-privileged port and use CoreDNS to forward queries to it.
The catch-all zone at the bottom is important — without it, CoreDNS acts as an open
DNS resolver and you will receive abuse complaints.

```nix
{ ... }:
{
  services.dnsseedrs.mainnet = {
    enable = true;
    chain = "main";
    seedDomain = "seed.example.com";
    serverName = "ns.example.com";
    soaRname = "admin.example.com";
    bind = [
      "udp://127.0.0.1:5353"
      "tcp://127.0.0.1:5353"
    ];
  };

  services.coredns = {
    enable = true;
    config = ''
      seed.example.com:53 {
        bind 0.0.0.0 ::
        forward . 127.0.0.1:5353
        any
        log
      }

      .:53 {
        bind 0.0.0.0 ::
        any
        template ANY ANY {
          rcode REFUSED
        }
        log
      }
    '';
  };
}
```

## DNSSEC

dnsseedrs can sign DNS responses when pointed at a directory containing keys
produced by `dnssec-keygen`. Since the public key must be registered as a DS
record with your domain registrar, keys should be generated offline and deployed
as secrets.

### 1. Generate keys

Generate a ZSK and KSK for your seed domain:

```bash
dnssec-keygen -a ECDSAP256SHA256 -n ZONE seed.example.com
dnssec-keygen -a ECDSAP256SHA256 -n ZONE -f KSK seed.example.com
```

This produces 4 files (the tags `XXXXX`/`YYYYY` will vary):
- `Kseed.example.com.+013+XXXXX.key` / `.private` (ZSK)
- `Kseed.example.com.+013+YYYYY.key` / `.private` (KSK)

### 2. Create the DS record for your registrar

```bash
dnssec-dsfromkey Kseed.example.com.+013+YYYYY.key
```

Submit the output as a DS record with your domain registrar.

### 3. Encrypt with sops

In your deployment repo (where `.sops.yaml` is configured), encrypt each key
file as binary:

```bash
mkdir -p secrets
for f in Kseed.example.com.+013+*.key Kseed.example.com.+013+*.private; do
  sops encrypt --input-type binary --output-type binary "$f" > "secrets/$f"
done
```

### 4. Deploy with sops-nix

```nix
{ config, ... }:
let
  keyDir = "/run/secrets/dnsseedrs-keys";
in
{
  sops.secrets."dnsseedrs-zsk-key" = {
    sopsFile = ./secrets/Kseed.example.com.+013+XXXXX.key;
    format = "binary";
    path = "${keyDir}/Kseed.example.com.+013+XXXXX.key";
    owner = "dnsseedrs";
    group = "dnsseedrs";
  };
  sops.secrets."dnsseedrs-zsk-private" = {
    sopsFile = ./secrets/Kseed.example.com.+013+XXXXX.private;
    format = "binary";
    path = "${keyDir}/Kseed.example.com.+013+XXXXX.private";
    owner = "dnsseedrs";
    group = "dnsseedrs";
  };
  sops.secrets."dnsseedrs-ksk-key" = {
    sopsFile = ./secrets/Kseed.example.com.+013+YYYYY.key;
    format = "binary";
    path = "${keyDir}/Kseed.example.com.+013+YYYYY.key";
    owner = "dnsseedrs";
    group = "dnsseedrs";
  };
  sops.secrets."dnsseedrs-ksk-private" = {
    sopsFile = ./secrets/Kseed.example.com.+013+YYYYY.private;
    format = "binary";
    path = "${keyDir}/Kseed.example.com.+013+YYYYY.private";
    owner = "dnsseedrs";
    group = "dnsseedrs";
  };

  services.dnsseedrs.mainnet = {
    enable = true;
    chain = "main";
    seedDomain = "seed.example.com";
    serverName = "ns.example.com";
    soaRname = "admin.example.com";
    dnssecKeys = keyDir;
  };

  systemd.services.dnsseedrs-mainnet = {
    after = [ "sops-install-secrets.service" ];
    wants = [ "sops-install-secrets.service" ];
  };
}
```

Replace `XXXXX` (ZSK tag) and `YYYYY` (KSK tag) with the actual key tags
from step 1.

## Service Management

```bash
# Status
systemctl status dnsseedrs-mainnet

# Logs
journalctl -u dnsseedrs-mainnet -f

# Restart
systemctl restart dnsseedrs-mainnet
```
