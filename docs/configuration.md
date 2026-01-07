# Configuration

RustyBGP reads a configuration file when `-f/--config-file` is provided.
The format is determined by file extension:

- `.yaml` / `.yml`: YAML via `serde_yaml`
- everything else: TOML via `toml`

The schema is generated from OpenConfig and GoBGP YANG models into
`daemon/src/config/gen.rs`, with validation in `daemon/src/config/validate.rs`.

## Required Fields

Validation enforces the following:

- `global.config.as` must be set and non-zero.
- `global.config.router-id` must be set and parse as an IPv4 address.
- Each neighbor must set `neighbor.config.peer-as` and
  `neighbor.config.neighbor-address`.

If any of these are missing, the daemon will fail to start.

## Minimal Example (YAML)

```yaml
global:
  config:
    as: 65001
    router-id: 203.0.113.1
neighbors:
  - config:
      neighbor-address: 198.51.100.2
      peer-as: 65002
```

## Minimal Example (TOML)

```toml
[global.config]
as = 65001
router-id = "203.0.113.1"

[[neighbors]]
[neighbors.config]
neighbor-address = "198.51.100.2"
peer-as = 65002
```

## Notable Sections

The following sections are actively consumed by the daemon in
`daemon/src/event.rs`:

- `neighbors`: configures static peers and their per-neighbor settings.
- `peer-groups`: defines groups for dynamic peers or shared policy.
- `dynamic-neighbors`: binds prefixes to a peer group for dynamic acceptance.
- `rpki-servers`: configures RPKI RTR connections.
- `bmp-servers`: configures BMP monitoring targets.
- `mrt-dump`: enables MRT update dumps.
- `defined-sets` and `policy-definitions`: routing policy primitives.

## Validation Constraints

Some additional constraints enforced in `validate.rs`:

- `bmp-servers.config.route-monitoring-policy` must be `pre-policy`.
- Neighbor-level `add-paths` is rejected; use per-AFI/SAFI config instead.

## Ports

Global listen port is currently set via gRPC `StartBgp` and defaults to 179
when using a config file. The generated schema contains a global `port` field,
but the current startup path does not consume it.

## Generating the Schema

If you need to regenerate the config schema:

- See `tools/pyang_plugins/README.md` for the YANG inputs and the command that
  produces `daemon/src/config/gen.rs`.
