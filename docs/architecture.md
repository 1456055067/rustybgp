# Architecture

This document summarizes how the daemon is structured based on the current
implementation in `daemon/src/event.rs`, `daemon/src/table.rs`, and
`daemon/src/packet/`.

## Threading Model

RustyBGP explicitly sizes its worker threads based on CPU count.

- Table threads: `num_cpus / 2` shards handle routing table processing.
- Peer worker threads: `num_cpus / 2 - 1` threads run peer handlers and their
  async runtimes.
- Management thread: the main thread runs the global server, gRPC service, and
  socket accept loop.

This maps to the design described in `DESIGN.md`, with routing table work
parallelized and peer I/O multiplexed in separate worker threads.

## Core Components

- Global state: `Global` holds ASN, router ID, peers, peer groups, and policy
  tables. It is accessed via a global `RwLock`.
- Routing tables: `table::RoutingTable` is sharded across table threads. Each
  shard tracks destinations and paths and performs best-path selection.
- Peer handlers: `Handler` processes a single BGP session, including state
  machine transitions, message encoding/decoding, and timers.

## Data Flow

1) A peer handler reads a BGP UPDATE, decodes it, and builds a route change.
2) The handler hashes the route and sends it to the appropriate table shard.
3) The table shard updates best-path state and notifies relevant peers.
4) Peer handlers encode outbound UPDATEs and send them on their TCP sessions.

Communication between threads uses Tokio `mpsc` channels. Each table shard owns
its own event receivers, and peer handlers hold senders for inter-thread
notifications.

## gRPC Control Plane

The gRPC service (`GoBgpService`) is hosted in the management thread. It
manages:

- Starting BGP with the global ASN and router ID.
- Adding/removing peers and peer groups.
- Reading routing table summaries.
- Policy and RPKI configuration.

The service listens on `0.0.0.0:50051` by default.

## Socket Lifecycle

- Passive accept: the daemon listens on TCP port 179 (default) and accepts new
  sessions into peer handlers.
- Active connect: configured peers are proactively connected in active mode.
- Dynamic peers: peers can be created from peer groups that contain dynamic
  neighbor prefixes.
