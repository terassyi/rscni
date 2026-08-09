# RsCNI

Rust libraries for both sides of [CNI (Container Network Interface)](https://www.cni.dev/) — writing plugins and invoking them — following the [CNI specification v1.1.0](https://github.com/containernetworking/cni/blob/v1.3.0/SPEC.md).

![CI](https://github.com/terassyi/rscni/workflows/CI/badge.svg)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## Crates

| Crate | Version | Use it to |
| --- | --- | --- |
| [`rscni-plugin`](./plugin) | [![crates.io](https://img.shields.io/crates/v/rscni-plugin.svg)](https://crates.io/crates/rscni-plugin) | Write a CNI plugin — the process a container runtime invokes |
| `rscni-runtime` | *planned* | Invoke CNI plugins — the Rust counterpart to Go's [`libcni`](https://github.com/containernetworking/cni/tree/v1.3.0/libcni) |
| [`rscni-types`](./types) | [![crates.io](https://img.shields.io/crates/v/rscni-types.svg)](https://crates.io/crates/rscni-types) | Work with the specification types on their own |

Both sides share `rscni-types`, so a plugin and a runtime built from this repository agree on the wire format by construction rather than by convention. Keeping them together also means each can serve as the other's reference implementation — `rscni-runtime` is tested by driving the `rscni-plugin`-based example plugins.

> [!IMPORTANT]
> **`rscni` has been renamed to `rscni-plugin`.**
>
> ```toml
> # before
> rscni = "0.2"
> # after
> rscni-plugin = "0.3"
> ```
>
> Then replace `rscni::` with `rscni_plugin::`. The module layout and feature names are unchanged. [`rscni` 0.3.0](./rscni) is a deprecated shim that re-exports `rscni-plugin` under the old paths so existing code keeps compiling; it will not be updated again.
>
> The rename happened because the bare name `rscni` did not say which side of CNI it implemented.

## Repository layout

```
rscni/
  types/      rscni-types    — CNI specification types, shared by both sides
  plugin/     rscni-plugin   — write a plugin
  compat/     rscni          — deprecated 0.3.0 shim for the rename
  examples/                  — example plugins (not published)
tests/
  integration/               — cross-crate tests (not published)
```

A cargo virtual workspace: each crate is versioned and released independently.

## Writing a plugin

Implement the `Cni` trait — `add`, `del`, `check`, `status`, `gc` — and hand it to
`Plugin::run`, which reads the `CNI_*` environment and stdin, dispatches, and writes the
result:

```rust
let plugin = Plugin::default().msg("My CNI Plugin v0.1.0");
plugin.run(&MyCniPlugin).expect("Failed to execute CNI command");
```

An async version is available behind the `async` feature. The
[`rscni-plugin` README](./plugin/README.md) has the full example for both,
installation, and the type reference.

## Examples

Complete working examples are in [`examples/`](./examples):

- [**rscni-debug**](./examples/rscni_debug.rs) - Synchronous CNI plugin for debugging
- [**async-rscni-debug**](./examples/async_rscni_debug.rs) - Asynchronous CNI plugin for debugging

```bash
# Build the debug plugin
cargo build --package rscni-examples

# Test with CNI environment
CNI_COMMAND=VERSION ./target/debug/rscni-debug
```

## Development

[`just`](https://github.com/casey/just) drives the common tasks:

```bash
just lint     # fmt and clippy across the workspace
just test     # unit, doc and integration tests
just build    # build every crate
just --list   # everything else
```

The example plugins come with a manual [kind](https://kind.sigs.k8s.io/) walkthrough —
`just examples::kind-up` installs one into a real cluster so you can watch it being
called. Its recipes live in [`examples/justfile`](./examples/justfile),
since they need docker and kind and never run in CI. See
[`examples/`](./examples).

## Releasing

Each crate releases independently, tagged `<crate>-v<version>` (for example `rscni-plugin-v0.3.0`). See [RELEASE.md](./RELEASE.md).

## License

RsCNI is licensed under the Apache License, Version 2.0. See [LICENSE](./LICENSE) for the full license text.
