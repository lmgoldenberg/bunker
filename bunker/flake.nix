{
	inputs = {
		nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
		flake-utils.url = "github:numtide/flake-utils";
	};

	outputs = { self, nixpkgs, flake-utils }:
		flake-utils.lib.eachDefaultSystem (system:
			let pkgs = import nixpkgs {
				inherit system;
			}; in {
				devShell = pkgs.mkShell {
					buildInputs = with pkgs; [
						cargo
						clippy
						cargo-outdated
						(python3.withPackages (p: with p; [
							websockets
							msgpack
							pycryptodome
							flask
							pyjwt
							requests
							sqlalchemy
						]))
						tpm2-tss
						pkg-config
						diesel-cli
						sqlite
					];
				};
			});
}
