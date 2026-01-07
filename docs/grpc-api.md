# gRPC API

RustyBGP implements the GoBGP gRPC API defined in `api/*.proto`. The daemon
exposes the service on:

- `0.0.0.0:50051` (default)

The gRPC service is compiled via `daemon/build.rs` using `tonic_prost_build`,
and included in the daemon at `daemon/src/main.rs`.

## Compatibility

The API is intended to be compatible with GoBGP. The GoBGP CLI (v3+) can manage
RustyBGP using the same commands you would use for a GoBGP daemon.

## Supported RPCs

The project README documents the following supported API surface:

- Global: `StartBgp`, `GetBgp`
- Peers: `AddPeer`, `DeletePeer`, `ListPeer`, `EnablePeer`, `DisablePeer`
- Peer groups: `AddPeerGroup`
- Dynamic neighbors: `AddDynamicNeighbor`
- RIB: `AddPath`, `DeletePath`, `ListPath`, `AddPathStream`, `GetTable`
- Policy: `AddPolicy`, `ListPolicy`, `AddDefinedSet`, `ListDefinedSet`,
  `AddStatement`, `ListStatement`, `AddPolicyAssignment`,
  `ListPolicyAssignment`
- RPKI: `AddRpki`, `ListRpki`, `ListRpkiTable`
- MRT: `EnableMrt`
- BMP: `AddBmp`, `ListBmp`

Some RPCs in `api/gobgp.proto` are currently unimplemented; consult
`daemon/src/event.rs` for the current status.

## Ports and Addresses

- gRPC: `0.0.0.0:50051`
- BGP TCP listener: 179 by default (can be set via `StartBgp`).
