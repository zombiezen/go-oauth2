{ pkgs ? import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/d639b2dfacdb3464faa11936a8c751ea3ff57775.tar.gz") {}
}:

pkgs.mkShell {
  packages = [
    pkgs.go_1_19
  ];
}
