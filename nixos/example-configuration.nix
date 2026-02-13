{ config, ... }:
let
  domain = "seed.example.com";
  keyDir = "/run/secrets/dnsseedrs-keys";
in
{
  services.dnsseedrs = {
    mainnet = {
      enable = true;
      chain = "main";
      seedDomain = domain;
      serverName = "ns.example.com";
      soaRname = "admin.example.com";
      seedNodes = [ "1.2.3.4:8333" ];
      threads = 32;
      dnssecKeys = keyDir;
      bind = [
        "udp://127.0.0.1:5353"
        "tcp://127.0.0.1:5353"
      ];
    };

    signet = {
      enable = true;
      chain = "signet";
      seedDomain = "signet-seed.example.com";
      serverName = "ns.example.com";
      soaRname = "admin.example.com";
      bind = [
        "udp://127.0.0.1:5354"
        "tcp://127.0.0.1:5354"
      ];
    };
  };

  # Deploy DNSSEC keys with sops-nix (replace XXXXX/YYYYY with actual key tags)
  sops.secrets."dnsseedrs-zsk-key" = {
    sopsFile = ./secrets + "/K${domain}.+013+XXXXX.key";
    format = "binary";
    path = "${keyDir}/K${domain}.+013+XXXXX.key";
    owner = "dnsseedrs";
    group = "dnsseedrs";
  };
  sops.secrets."dnsseedrs-zsk-private" = {
    sopsFile = ./secrets + "/K${domain}.+013+XXXXX.private";
    format = "binary";
    path = "${keyDir}/K${domain}.+013+XXXXX.private";
    owner = "dnsseedrs";
    group = "dnsseedrs";
  };
  sops.secrets."dnsseedrs-ksk-key" = {
    sopsFile = ./secrets + "/K${domain}.+013+YYYYY.key";
    format = "binary";
    path = "${keyDir}/K${domain}.+013+YYYYY.key";
    owner = "dnsseedrs";
    group = "dnsseedrs";
  };
  sops.secrets."dnsseedrs-ksk-private" = {
    sopsFile = ./secrets + "/K${domain}.+013+YYYYY.private";
    format = "binary";
    path = "${keyDir}/K${domain}.+013+YYYYY.private";
    owner = "dnsseedrs";
    group = "dnsseedrs";
  };

  systemd.services.dnsseedrs-mainnet = {
    after = [ "sops-install-secrets.service" ];
    wants = [ "sops-install-secrets.service" ];
  };

  # CoreDNS forwards seed domain queries to dnsseedrs.
  # The catch-all zone refuses everything else to avoid being an open resolver.
  services.coredns = {
    enable = true;
    config = ''
      ${domain}:53 {
        bind 0.0.0.0 ::
        forward . 127.0.0.1:5353
        any
        log
      }

      signet-seed.example.com:53 {
        bind 0.0.0.0 ::
        forward . 127.0.0.1:5354
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
