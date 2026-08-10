# rscni-types

[![crates.io](https://img.shields.io/crates/v/rscni-types.svg)](https://crates.io/crates/rscni-types)
[![docs.rs](https://docs.rs/rscni-types/badge.svg)](https://docs.rs/rscni-types)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/terassyi/rscni/blob/main/LICENSE)

Shared [CNI (Container Network Interface)](https://www.cni.dev/) specification types for Rust, following the [CNI specification v1.1.0](https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md).

This crate holds the data structures and error type the specification defines, and nothing else. It knows how to represent a CNI conversation but never takes part in one.

## Which crate do you want?

| Crate | Use it to |
| --- | --- |
| [`rscni-plugin`](https://crates.io/crates/rscni-plugin) | Write a CNI plugin — the process a container runtime invokes |
| `rscni-runtime` (planned) | Invoke CNI plugins — the Rust counterpart to Go's `libcni` |
| `rscni-types` | Work with the specification types on their own |

Both of the above depend on this crate and re-export its types, so a plugin and a runtime built with them agree on the wire format by construction. You depend on `rscni-types` directly when you want the types without either side's machinery — parsing a `.conflist` file, for example.

## Installation

```toml
[dependencies]
rscni-types = "0.1"
```

## Contents

- `types` — network configuration (`NetConf`, `NetConfList`), results (`CNIResult`, `Interface`, `IpConfig`, `Route`, `Dns`), `Cmd`, and the `CNI_*` environment variable names
- `error` — `Error`, covering the specification's error codes 1–7, 11, 50 and 51
- `version` — `PluginInfo` and version negotiation

`NetConf` keeps unrecognized fields in a flattened `custom: HashMap<String, Value>`, so plugin-specific configuration passes through without this crate knowing about it.

## Supported specification versions

v0.3.0, v0.3.1, v0.4.0, v1.0.0 and v1.1.0.

## License

Apache-2.0. See [LICENSE](https://github.com/terassyi/rscni/blob/main/LICENSE).
