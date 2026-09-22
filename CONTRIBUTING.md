# Contributing to zkUnderwrite

Thanks for your interest in contributing. This document covers how the
repository is laid out and how to build and check each part of it.

## Repository layout

There is no root Cargo workspace. The repository has five independent Cargo
roots, each built from its own directory — see the "Cargo roots" section of
[`README.md`](README.md) for the full table. In short:

| Root | Builds | How to build |
|---|---|---|
| `issuer/` | `zku-issuer`, the Ed25519 issuer CLI (`keygen`, `sign`) | `cd issuer && cargo build --release` |
| `zkvm/` | workspace of `host` (borrower CLI) and `methods` (embeds the guest) | inside the RISC Zero container: `cd zkvm && cargo build --release -p host` |
| `zkvm/methods/guest/` | `zku-guest`, the zkVM guest | built automatically as part of the `zkvm/` build, not by hand |
| `contracts/zkunderwrite/` | the Soroban app contract | `cd contracts/zkunderwrite && stellar contract build` |
| `reference-verifier/` | vendored Nethermind verifier stack | see `reference-verifier/README.md` |

`Cargo.lock` is committed for `issuer/`, `zkvm/` and `contracts/zkunderwrite/`,
so builds there are reproducible. The vendored `reference-verifier/` and the
detached `zkvm/methods/guest/` crate keep their lockfiles ignored.

## Development setup

Install the toolchain pinned by the root `rust-toolchain.toml` (stable
channel, `rustfmt`/`clippy` components, `wasm32v1-none` target):

```bash
rustup show active-toolchain || rustup toolchain install
```

The RISC Zero toolchain (`rzup`) ships no Intel-macOS binary, so guest builds
and proving run in a `linux/amd64` container:

```bash
docker build --platform linux/amd64 -f Dockerfile.risc0 -t zku-risc0 .
```

Stellar contract work (`contracts/zkunderwrite/`) and the issuer CLI
(`issuer/`) run natively on any platform with the Rust toolchain above and,
for the contract, the Stellar CLI.

## Making changes

- Work from the relevant Cargo root (`issuer/`, `contracts/zkunderwrite/`,
  `zkvm/`, or `reference-verifier/`) — each has its own `Cargo.toml` and is
  checked independently in CI (`.github/workflows/ci.yml`).
- Before opening a pull request, run `cargo fmt`, `cargo clippy` and
  `cargo test` from within the Cargo root(s) you touched.
- `reference-verifier/` is a vendored dependency; avoid changing its sources
  unless the change is required to keep it usable as the contract's
  `interface` path dependency. See `reference-verifier/CONTRIBUTING.md` for
  its own contribution process.
- Keep pull requests focused on a single change. Use the pull request
  template and fill in every section.

## Reporting issues

Open a GitHub issue describing the problem, the affected Cargo root, and
steps to reproduce. Use the issue templates in `.github/ISSUE_TEMPLATE/` for
bug reports and feature requests.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating, you are expected to uphold it.
