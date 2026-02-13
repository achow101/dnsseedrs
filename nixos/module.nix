{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.dnsseedrs;
  enabledInstances = lib.filterAttrs (_: icfg: icfg.enable) cfg;
in
{
  options.services.dnsseedrs = lib.mkOption {
    type = lib.types.attrsOf (
      lib.types.submodule {
        options = {
          enable = lib.mkEnableOption "dnsseedrs DNS seeder instance";

          package = lib.mkPackageOption pkgs "dnsseedrs" { };

          chain = lib.mkOption {
            type = lib.types.enum [
              "main"
              "test"
              "testnet4"
              "signet"
            ];
            description = "Bitcoin network to connect to.";
          };

          seedDomain = lib.mkOption {
            type = lib.types.str;
            description = "Domain name for which this server returns results.";
          };

          serverName = lib.mkOption {
            type = lib.types.str;
            description = "Domain name of this server (NS record target).";
          };

          soaRname = lib.mkOption {
            type = lib.types.str;
            description = "String for the rname field of the SOA record.";
          };

          seedNodes = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [ ];
            description = "Initial seed nodes to connect to.";
          };

          dbFile = lib.mkOption {
            type = lib.types.str;
            default = "sqlite.db";
            description = "SQLite database filename (relative to state directory).";
          };

          dumpFile = lib.mkOption {
            type = lib.types.str;
            default = "seeds.txt";
            description = "Dump file for known good addresses.";
          };

          noIpv4 = lib.mkOption {
            type = lib.types.bool;
            default = false;
            description = "Disable IPv4 address crawling.";
          };

          noIpv6 = lib.mkOption {
            type = lib.types.bool;
            default = false;
            description = "Disable IPv6 address crawling.";
          };

          cjdnsReachable = lib.mkOption {
            type = lib.types.bool;
            default = false;
            description = "Enable CJDNS reachability.";
          };

          onionProxy = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
            description = "Tor SOCKS5 proxy address (e.g. 127.0.0.1:9050).";
          };

          i2pProxy = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
            description = "I2P SOCKS5 proxy address (e.g. 127.0.0.1:4447).";
          };

          threads = lib.mkOption {
            type = lib.types.ints.positive;
            default = 24;
            description = "Number of crawler threads.";
          };

          bind = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [ ];
            description = "Addresses to bind for DNS (e.g. udp://0.0.0.0:53). Empty uses CLI defaults.";
          };

          dnssecKeys = lib.mkOption {
            type = lib.types.nullOr lib.types.path;
            default = null;
            description = "Path to directory containing DNSSEC keys from dnssec-keygen.";
          };

          asmap = lib.mkOption {
            type = lib.types.nullOr lib.types.path;
            default = null;
            description = "Path to an asmap file for AS-aware bucketing.";
          };

          extraArgs = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [ ];
            description = "Additional command-line arguments.";
          };
        };
      }
    );
    default = { };
    description = "dnsseedrs DNS seeder instances.";
  };

  config = lib.mkIf (enabledInstances != { }) {
    users.users.dnsseedrs = {
      isSystemUser = true;
      group = "dnsseedrs";
    };
    users.groups.dnsseedrs = { };

    systemd.services = lib.mapAttrs' (
      name: icfg:
      lib.nameValuePair "dnsseedrs-${name}" {
        description = "dnsseedrs DNS seeder (${name})";
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];

        serviceConfig =
          let
            args =
              lib.cli.toCommandLineGNU { } (
                lib.filterAttrs (_: v: v != null) {
                  chain = icfg.chain;
                  seednode = icfg.seedNodes;
                  db-file = icfg.dbFile;
                  dump-file = icfg.dumpFile;
                  no-ipv4 = icfg.noIpv4;
                  no-ipv6 = icfg.noIpv6;
                  cjdns-reachable = icfg.cjdnsReachable;
                  onion-proxy = icfg.onionProxy;
                  i2p-proxy = icfg.i2pProxy;
                  threads = icfg.threads;
                  bind = icfg.bind;
                  dnssec-keys = icfg.dnssecKeys;
                  asmap = icfg.asmap;
                }
              )
              ++ icfg.extraArgs
              ++ [
                icfg.seedDomain
                icfg.serverName
                icfg.soaRname
              ];
          in
          {
            ExecStart = "${lib.getExe icfg.package} ${lib.escapeShellArgs args}";
            User = "dnsseedrs";
            Group = "dnsseedrs";
            StateDirectory = "dnsseedrs/${name}";
            WorkingDirectory = "/var/lib/dnsseedrs/${name}";

            Restart = "always";
            RestartSec = "10s";

            AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
            CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
            NoNewPrivileges = true;
            ProtectSystem = "strict";
            ProtectHome = true;
            PrivateTmp = true;
            PrivateDevices = true;
            ProtectKernelTunables = true;
            ProtectKernelModules = true;
            ProtectControlGroups = true;
            RestrictSUIDSGID = true;
            RestrictNamespaces = true;
            LockPersonality = true;
            MemoryDenyWriteExecute = true;
            RestrictRealtime = true;
          };
      }
    ) enabledInstances;
  };
}
