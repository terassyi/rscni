# CLAUDE.md

Implementation policies for this repository, set by the owner.

## Code design

- Do not write functions detached from a type. Implement logic as methods or associated functions (the only exception: serde requires a function path).
- Do not add a custom method when a standard trait can do the job.
- Prefer type safety. Use dedicated types instead of passing strings around, and do not keep needless strings as struct members. Do not change existing public signatures without approval.
- Keep the public API minimal. Always question whether `pub` is needed. Do not put test-only code in public modules.
- Do not degrade production code for the convenience of tests.
- Do not swallow errors outside test code.
- No pointless refactoring. Removing redundant code is fine.
- Keep doc comments and signatures short. Write explicit version ranges, not vague terms.

## Tests

- Do not write pointless tests. Do not over-grow the test suite. Keep tests simple.
- Use rstest `#[case]` tables for tabular cases.

## Conformance

- The CNI spec and the Go reference implementation (containernetworking/cni) are the yardstick. When they disagree, the spec wins; document intentional deviations with their rationale in comments or the PR.
- Match the Go library's external behavior only: wire formats, error codes, and observable I/O. Do not mirror its internal implementation details. Write idiomatic Rust.

## Workflow

- Never mix version bumps into code-change PRs. Bump in a separate PR.
- PRs must not depend on each other. Always base them on main.
- Do not edit files with scripting languages or shell text tools (python, perl, sed, and the like). Use the Edit/Write tools.
- Judge every proposal on its merits, regardless of who made it. Raise objections before implementing.
- Commit, push, and create PRs only with the owner's approval.
