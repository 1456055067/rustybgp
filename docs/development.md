# Development

This document focuses on build internals, code generation, and testing.

## Workspace Layout

- Root `Cargo.toml` defines a single workspace member: `daemon`.
- The daemon binary crate is `daemon/` (`rustybgpd`).

## Build Script

`daemon/build.rs` does two important things:

- Captures the current Git hash (`GIT_HASH`) for the version string.
- Compiles gRPC stubs from `api/*.proto` using `tonic_prost_build`.

Because of this, a working `git` binary is required at build time.

## Config Schema Generation

`daemon/src/config/gen.rs` is generated from OpenConfig and GoBGP YANG models.
The generation workflow is documented in `tools/pyang_plugins/README.md`, which
includes the exact `pyang` invocation.

## Tests

The repository includes a small packet fixture in
`daemon/tests/packet/ipv6-update.raw`. Additional integration test tooling is
referenced in `BUILD.md` under `tests/integration/functional/local-ci.sh`.

## Linting and Formatting

No repository-specific lint/format commands are defined in this checkout.
Use standard Rust tooling (`cargo fmt`, `cargo clippy`) as needed.
