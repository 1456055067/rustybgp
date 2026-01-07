# Codebase Tour

This is a quick map of the main directories and modules.

## Top Level

- `api/`: GoBGP gRPC proto files used by the daemon.
- `daemon/`: The RustyBGP daemon crate.
- `tools/pyang_plugins/`: YANG-to-Rust generator for config schema.
- `BUILD.md` / `DESIGN.md` / `README.md`: project documentation.

## `daemon/` Modules

- `daemon/src/main.rs`: CLI entrypoint and bootstrap.
- `daemon/src/event.rs`: core runtime, gRPC server, peer handling, and timers.
- `daemon/src/table.rs`: routing table, best-path logic, and policy hooks.
- `daemon/src/packet/`: protocol encoders/decoders for BGP/BMP/MRT/RPKI.
- `daemon/src/config/`: generated schema (`gen.rs`) and validation (`validate.rs`).
- `daemon/src/auth.rs`: TCP MD5 signature handling (Linux).
- `daemon/src/proto.rs`: helpers for translating to API types.
- `daemon/src/error.rs`: error types mapped to gRPC status codes.

## gRPC APIs

- `api/gobgp.proto` defines the `GoBgpService` service and request/response
  types.
- `daemon/build.rs` compiles these protos into Rust code with `tonic`.
