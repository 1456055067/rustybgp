# Getting Started

This guide is focused on building and running the RustyBGP daemon in this
repository.

## Build

The top-level `README.md` shows a Docker-based build that does not require a
local Rust toolchain. For local development and CI, see `BUILD.md`.

### Docker (musl) build

```bash
git clone https://github.com/osrg/rustybgp.git
cd rustybgp
docker pull ghcr.io/rust-cross/rust-musl-cross:x86_64-unknown-linux-musl
docker run --rm -it -v "$(pwd)":/home/rust/src \
  ghcr.io/rust-cross/rust-musl-cross:x86_64-unknown-linux-musl \
  cargo build --release
```

The binary is placed at:

```
target/x86_64-unknown-linux-musl/release/rustybgpd
```

## Run

The daemon requires at least 4 CPUs at startup (`daemon/src/main.rs` enforces
this).

### Run with a config file

```bash
sudo ./target/x86_64-unknown-linux-musl/release/rustybgpd \
  -f gobgpd.conf
```

The config file can be YAML or TOML. See `docs/configuration.md` for details.

### Run with CLI arguments

```bash
sudo ./target/x86_64-unknown-linux-musl/release/rustybgpd \
  --as-number 65001 \
  --router-id 203.0.113.1
```

If `--as-number` is used, `--router-id` is required.

If you start the daemon without a config file and without `--as-number`, it
waits for `StartBgp` over gRPC before opening BGP listeners.

### Accept any peers

```bash
sudo ./target/x86_64-unknown-linux-musl/release/rustybgpd \
  --as-number 65001 \
  --router-id 203.0.113.1 \
  --any-peers
```

The `--any-peers` flag creates a dynamic peer group that accepts all IPv4 and
IPv6 peers (`0.0.0.0/0` and `::/0`).

## Ports

- BGP listen port: 179 by default (`Global::BGP_PORT`).
- gRPC listen port: `0.0.0.0:50051`.

## CLI Flags

- `-f`, `--config-file`: path to TOML/YAML config.
- `--as-number`: local ASN (required with `--router-id`).
- `--router-id`: local router ID (IPv4 address string).
- `--any-peers`: accept peers not explicitly configured.

## gRPC Client

RustyBGP speaks the GoBGP gRPC API. You can use the GoBGP CLI to interact with
the daemon after it starts. See `docs/grpc-api.md` for details.
