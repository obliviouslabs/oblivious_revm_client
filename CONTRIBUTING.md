# Contributing

Contributions are welcome through GitHub issues and pull requests.

## Development setup

Clone the verifier submodule and install the browser dependencies:

```bash
git submodule update --init --recursive
cd crates/safe-node-revm-wasm
npm install --include=dev
cd ../..
```

The repository pins Rust in `rust-toolchain.toml`. Before opening a pull
request, run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo check -p safe-node-revm-wasm --target wasm32-unknown-unknown
(cd crates/safe-node-revm-wasm && npm run lint && npm test)
```

If Docker, curl, and OpenSSL are available, also run:

```bash
(cd crates/safe-node-revm-wasm && npm run test:pinning)
```

The Playwright test additionally requires `wasm-pack` and Chromium; see the
README for setup commands.

## Live tests and sensitive data

Live endpoint tests are opt-in and must only use a freshly attested TLS pin.
Never commit pins, generated KPS keys, `.env`, deployment credentials, private
API keys, attestation tokens, or production query data. The API path committed
in `.env.example` is a deliberately public, rate-limited development endpoint.

Changes to cadence, request shape, proof verification, attestation policy, or
TLS verification should include focused tests and an update to `SECURITY.md`
when they alter a trust or privacy boundary.
