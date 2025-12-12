# Release Process

This document describes the release process for rscni.

## Release Steps

### 1. Fetch the latest revision

```bash
git switch main
git pull origin main
```

### 2. Update Version

Update version in Cargo.toml and docs.

### 2. Run Tests

```bash
# Verify all tests pass
cargo test --lib
cargo test --lib --features async
cargo test --doc
cargo test --test plugin_integration_test

# Lint checks
cargo fmt --all -- --check
cargo clippy --all-features -- -D warnings
```

### 3. Create a Release Pull Request

```bash
VERSION=x.y.z
git switch -c bump-$VERSION
git commit -a -s -m "bump version to v$VERSION"
gh pr create --fill
```

### 4. Merge Release PR

Merge its PR.

```bash
VERSION=x.y.z
git switch main
git pull origin main
git tag -a -m "Release v$VERSION" "v$VERSION"
# Make sure the tag exists
git tag -ln | grep $VERSION
git push origin "v$VERSION"
```

### 5. Edit GitHub Release

1. Ensure the release is created on https://github.com/terassyi/rscni/releases/tag/vx.y.z.
2. Edit contents.

### 6. Publish to crates.io (Manual Trigger)

Manually execute from GitHub Actions:

1. Go to "Actions" and select `publish`
2. Click "Run workflow" with version number and dry-run
3. Click "Run workflow" with version number and without dry-run
4. Check: https://crates.io/crates/rscni
