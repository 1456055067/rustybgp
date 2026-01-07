# Protocol Support

This document summarizes protocol-level support based on the code under
`daemon/src/packet/` and the startup logic in `daemon/src/event.rs`.

## BGP

The core BGP message parser and encoder live in `daemon/src/packet/bgp.rs`.

Key points:

- Address families: IPv4 and IPv6 unicast (`Family::IPV4`, `Family::IPV6`).
- Message types: OPEN, UPDATE, NOTIFICATION, KEEPALIVE, and ROUTE-REFRESH.
- Capabilities handled in code:
  - Multiprotocol
  - Route Refresh and Enhanced Route Refresh
  - Extended Nexthop
  - Graceful Restart
  - Four-octet ASN
  - Add-Path
  - Long-Lived Graceful Restart
  - FQDN

Update processing and best-path selection are in `daemon/src/table.rs`.

## BMP (BGP Monitoring Protocol)

BMP encoding/transport is under `daemon/src/packet/bmp.rs`, and BMP client
startup is handled in `daemon/src/event.rs` by `bmp-servers` config. Validation
currently enforces `pre-policy` route monitoring.

## MRT

MRT dump support is implemented in `daemon/src/packet/mrt.rs` and wired up via
the `mrt-dump` config section. Only `updates` dump type is accepted.

## RPKI RTR

RPKI support is implemented in `daemon/src/packet/rpki.rs` and managed via
`rpki-servers` configuration or gRPC API calls.
