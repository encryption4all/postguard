let
  moz_overlay = import (builtins.fetchTarball https://github.com/mozilla/nixpkgs-mozilla/archive/master.tar.gz);
  pkgs = import <nixpkgs> { overlays = [ moz_overlay ]; };
in pkgs.stdenv.mkDerivation {
  pname = "cryptify-env";
  version = "0.1";

  src = ./.;

  propagatedBuildInputs = [
    pkgs.nodejs-12_x
    pkgs.nodePackages.typescript
    pkgs.nodePackages.create-react-app
    pkgs.nodePackages.webpack
    pkgs.nodePackages.webpack-cli
    pkgs.wasm-pack
  ];

  buildPhase = ''
    :
  '';

  installPhase = ''
    :
  '';
}
