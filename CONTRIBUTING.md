# Contributing to ClipVault

ClipVault is in early development. Contributions are welcome, the most useful right now are bug reports, feature ideas, and small fixes. Large rewrites are out of scope until Milestone 1 lands.

## Toolchain

ClipVault uses the latest stable Rust, minimum 1.95.0.

```fish
rustup default stable
rustup component add rustfmt clippy
```

## Tooling

ClipVault uses these tools during development and release. The last four (`cargo-machete`, `cargo-release`, `cargo-dist`, `cargo-llvm-cov`) are mostly used during releases — install them if you plan to cut a release.

| Tool | Purpose |
|---|---|
| `rustfmt` | Code formatter |
| `clippy` | Linter |
| `cargo-audit` | Scans `Cargo.lock` for known vulnerabilities |
| `cargo-deny` | Enforces licence allow-list, ban-list, and version policy |
| `cargo-machete` | Finds unused dependencies |
| `cargo-release` | Bumps workspace versions and tags releases |
| `cargo-dist` | Builds release artefacts |
| `cargo-llvm-cov` | Generates code coverage reports |

Install the cargo tools with:

```fish
cargo install cargo-audit cargo-deny cargo-machete cargo-release cargo-dist cargo-llvm-cov
```

## Local quality gates

Run these checks locally before pushing:

```fish
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo check --workspace
cargo test --workspace
```

The same checks run in CI. Fixing them locally first saves a round trip.

## Workflow

ClipVault uses trunk-based development with feature branches.

- Branch from `main` with a conventional name: `feat/short-description`, `fix/short-description`, `chore/short-description`, `docs/short-description`.
- Commits follow [Conventional Commits](https://www.conventionalcommits.org/): `type(scope): description`. Common types are `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `ci`, `build`.
- Open a pull request against `main`. The PR title also follows Conventional Commits — it becomes the squash-merge commit message.
- Merge with Squash and merge. The feature branch is deleted after merge.

## Code style

- British English in doc comments and prose (licence, behaviour, organise, initialise).
- Every public item has a `///` doc comment. Crates and modules start with `//!`.
- Prefer iterator chains (`.filter_map`, `.find_map`) over `for` loops where idiomatic.
- No `unwrap()` outside tests. Use `?` and propagate errors.
- No `clone()` without a comment explaining why borrowing isn't enough.
- Use `todo!()` for unimplemented placeholders, not empty function bodies.

## Further reading

The current implementation plan and roadmap live in [`docs/milestone-1-plan.md`](docs/milestone-1-plan.md).
