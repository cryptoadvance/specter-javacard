{ pkgs ? import <nixpkgs> {} }:
  pkgs.mkShell {
    nativeBuildInputs = [ 
      pkgs.buildPackages.python39
      pkgs.openjdk8-bootstrap
    ];
    hardeningDisable = ["all"];
}
