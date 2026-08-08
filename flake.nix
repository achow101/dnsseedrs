{
  description = "dnsseedrs - Bitcoin DNS seeder";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        dnsseedrs = pkgs.callPackage ./default.nix { };
      in
      {
        packages.default = dnsseedrs;
        devShells.default = pkgs.mkShell {
          inputsFrom = [ dnsseedrs ];
          packages = [ pkgs.rust-analyzer ];
        };
      }
    )
    // {
      nixosModules.default = import ./nixos/module.nix;
      overlays.default = final: _prev: {
        dnsseedrs = final.callPackage ./default.nix { };
      };
    };
}
