# rscni-types

[![crates.io](https://img.shields.io/crates/v/rscni-types.svg)](https://crates.io/crates/rscni-types)
[![docs.rs](https://docs.rs/rscni-types/badge.svg)](https://docs.rs/rscni-types)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/terassyi/rscni/blob/main/LICENSE)

Shared [CNI (Container Network Interface)](https://www.cni.dev/) specification types for Rust, following the [CNI specification v1.1.0](https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md).

This crate holds the data structures and error type the specification defines, and nothing else. It contains no code that invokes a plugin, and none that is invoked as one.

## Which crate do you want?

| Crate | Use it to |
| --- | --- |
| [`rscni-plugin`](https://crates.io/crates/rscni-plugin) | Write a CNI plugin — the process a container runtime invokes |
| `rscni-runtime` (planned) | Invoke CNI plugins — the Rust counterpart to Go's `libcni` |
| `rscni-types` | Work with the specification types on their own |

`rscni-plugin` depends on this crate and re-exports its types, and `rscni-runtime` will do the same. A plugin and a runtime built with them therefore agree on the wire format. Depend on `rscni-types` directly when you want the types without either side's machinery, for example to parse a `.conflist` file.

## Installation

```toml
[dependencies]
rscni-types = "0.2"
```

## Contents

- `types` — network configuration (`NetConf`, `NetConfList`), results (`CNIResult`, `Interface`, `IpConfig`, `Route`, `Dns`), `Cmd`, and the `CNI_*` environment variable names
- `legacy` — the result layout of specification versions 0.3.0 through 0.4.0
- `error` — `Error`, covering the specification's error codes and plugin-defined ones
- `version` — `PluginInfo` and version negotiation

`NetConf` keeps unrecognized fields in a flattened `custom: HashMap<String, Value>`, so plugin-specific configuration passes through without this crate knowing about it.

## Supported specification versions

v0.3.0, v0.3.1, v0.4.0, v1.0.0 and v1.1.0.

## License

Apache-2.0. See [LICENSE](https://github.com/terassyi/rscni/blob/main/LICENSE).
