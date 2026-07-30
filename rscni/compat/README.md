# rscni

> [!WARNING]
> **This crate has been renamed to [`rscni-plugin`](https://crates.io/crates/rscni-plugin).**
>
> Version 0.3.0 exists only to ease that rename and will not be updated again.

`rscni` 0.3.0 re-exports `rscni-plugin` under the module paths 0.2.x used, so existing code keeps compiling while you migrate.

## Migrating

```toml
# before
rscni = "0.2"
# after
rscni-plugin = "0.3"
```

Then replace `rscni::` with `rscni_plugin::`. The module layout is unchanged, so `rscni::cni::Plugin` becomes `rscni_plugin::cni::Plugin`, `rscni::types::Args` becomes `rscni_plugin::types::Args`, and so on. Feature names (`std`, `async`) are unchanged too.

> [!NOTE]
> Naming `Plugin` through this shim emits a deprecation warning — that is how the rename reaches you. Under `#![deny(warnings)]` or `deny(deprecated)` that warning is a compile error, so either migrate right away or hold the build together with a temporary `#[allow(deprecated)]`.

## Why the rename

The [rscni repository](https://github.com/terassyi/rscni) now covers both sides of a CNI conversation, and the bare name `rscni` did not say which side it was:

| Crate | Role |
| --- | --- |
| [`rscni-plugin`](https://crates.io/crates/rscni-plugin) | Write a CNI plugin — the process a container runtime invokes |
| `rscni-runtime` (planned) | Invoke CNI plugins — the Rust counterpart to Go's `libcni` |
| [`rscni-types`](https://crates.io/crates/rscni-types) | The specification types both of the above share |

## License

Apache-2.0. See [LICENSE](https://github.com/terassyi/rscni/blob/main/LICENSE).
