# RsCNI

RsCNI is a CNI plugin library for Rust.
This is based on [containernetworking/cni](https://github.com/containernetworking/cni).

![GitHub release](https://img.shields.io/github/release/terassyi/rscni.svg?maxAge=60)
[![crate-name at crates.io](https://img.shields.io/crates/v/rscni.svg)](https://crates.io/crates/rscni)
[![crate-name at docs.rs](https://docs.rs/rscni/badge.svg)](https://docs.rs/rscni)
![CI](https://github.com/terassyi/sart/workflows/ci/badge.svg)

> [!WARNING]
> RsCNI is under experimental.

## Use

RsCNI has a similar APIs to [containernetworking/cni/pkg/skel](https://pkg.go.dev/github.com/containernetworking/cni/pkg/skel).

The entrypoint structure is `Plugin`.
It accepts callback functions defined as `CmdFn` to represent CNI Add, Del and Check commands.

```rust
pub struct Plugin {
    add: CmdFn,
    del: CmdFn,
    check: CmdFn,
    version_info: PluginInfo,
    about: String,
    dispatcher: Dispatcher,
}
```

`CmdFn` is the type for CNI commands.
It is the function type that accepts `Args` that is CNI arguments and return `CNIResult` or `Error`.
As we implement some functions satisfy this type, we can build our own CNI plugin.

```rust
pub type CmdFn = fn(args: Args) -> Result<CNIResult, Error>;
```

To run `Plugin`, we can call `run()` method like following.

```rust
fn main() {
    let version_info = PluginInfo::default();
    let mut dispatcher = Plugin::new(add, del, check, version_info, ABOUT_MSG);

    dispatcher.run().expect("Failed to complete the CNI call");
}
```

For details, please see [examples/rscni-debug](./examples/README.md).


## License
RsCNI is licensed under the Apache License, Version 2.0. See [LICENSE](./LICENSE) for the full license text.
