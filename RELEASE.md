# Release Process

This document describes the release process for the crates in this repository.

## Crates and tags

Each crate is versioned and released independently. Tags are `<crate>-v<version>`:

| Crate | Directory | Example tag |
| --- | --- | --- |
| `rscni-types` | `rscni/types` | `rscni-types-v0.1.0` |
| `rscni-plugin` | `rscni/plugin` | `rscni-plugin-v0.3.0` |
| `rscni` (deprecated shim) | `rscni/compat` | `rscni-v0.3.0` |
| `rscni-runtime` (planned) | `rscni/runtime` | `rscni-runtime-v0.1.0` |

When a crate is added, it needs adding to the root `members`, to `publish.yaml`'s `crate`
choices, to the `cargo package` list in `justfile` / `ci.yaml` / `release.yaml`, and as a
row in `ci.yaml`'s unit-test matrix. The lint command and `release.yaml`'s tests use
`--workspace` and pick it up on their own.

Tags `v0.1.0` through `v0.2.1` predate the workspace split and used a bare-version scheme.
They are left as they are; `release.yaml` only matches the new form.

## Dependency order

crates.io rejects a crate whose dependencies are not published yet, so release in this
order and let each one land before starting the next:

```
rscni-types  ←  rscni-plugin  ←  rscni (shim)
             ←  rscni-runtime
```

Only the crates whose version actually changed need releasing. If a change is confined to
`rscni-plugin`, release `rscni-plugin` alone.

Every path dependency carries a `version` alongside its `path`, which is what lets cargo
rewrite it into a registry dependency at publish time. Dropping the `version` makes
`cargo publish` fail.

## Release Steps

### 1. Fetch the latest revision

```bash
git switch main
git pull origin main
```

### 2. Update Version

Update `version` in the crate's own `Cargo.toml`, in any manifest that depends on it (for
example the `rscni-types` requirement in `rscni/plugin/Cargo.toml`), and in the docs that
name the version.

### 3. Run Tests

```bash
just lint
just test
just package   # every publishable crate packages cleanly
```

### 4. Create a Release Pull Request

```bash
CRATE=rscni-plugin
VERSION=x.y.z
git switch -c bump-$CRATE-$VERSION
git commit -a -s -m "bump $CRATE to v$VERSION"
gh pr create --fill
```

### 5. Merge Release PR

Merge its PR.

```bash
CRATE=rscni-plugin
VERSION=x.y.z
git switch main
git pull origin main
git tag -a -m "Release $CRATE v$VERSION" "$CRATE-v$VERSION"
# Make sure the tag exists
git tag -ln | grep "$CRATE-v$VERSION"
git push origin "$CRATE-v$VERSION"
```

Pushing the tag runs `release.yaml`, which re-checks that the tag version matches the
crate's manifest and then creates the GitHub Release.

### 6. Edit GitHub Release

1. Ensure the release is created on https://github.com/terassyi/rscni/releases/tag/CRATE-vx.y.z.
2. Edit contents.

### 7. Publish to crates.io (Manual Trigger)

Manually execute from GitHub Actions:

1. Go to "Actions" and select `publish`
2. Click "Run workflow", choose the crate, enter the version, and leave dry-run enabled
3. Click "Run workflow" again with the same inputs and dry-run disabled
4. Check: https://crates.io/crates/CRATE

Repeat for each crate being released, in the dependency order above.
