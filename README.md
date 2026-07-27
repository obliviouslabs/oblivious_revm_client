# Safe Node `revm` client

[![CI](https://github.com/obliviouslabs/oblivious_revm_client/actions/workflows/ci.yml/badge.svg)](https://github.com/obliviouslabs/oblivious_revm_client/actions/workflows/ci.yml)

> [!WARNING]
> This is experimental, unaudited software. Review the trust model and privacy
> limitations before using it with sensitive workloads.

A small Rust database adapter that lets [`revm`](https://github.com/bluealloy/revm)
read account and storage state from Safe Node's proof-only `eth_getProof` API.
It authenticates the TDX-discovered TLS public key, verifies every account and
storage MPT proof against a trusted block state root, and sends cover requests at
a fixed cadence while the worker is running.

## Workspace

- `crates/safe-node-revm` — RPC types, MPT verification, deterministic cadence
  queue, native pinned transport, and `revm::Database` adapter.
- `crates/safe-node-revm-cli` — first-contact verifier and a Sepolia WETH9
  execution example.
- `crates/safe-node-revm-wasm` — replay-on-cache-miss WASM executor, KPS browser
  wrapper, local KPS fixture/proxy, and Playwright smoke test.
- `external/tdx_easy_https` — pinned upstream verifier submodule.

## Prerequisites

- Rust 1.91.1 (installed automatically by `rust-toolchain.toml`)
- Git with submodule support
- Node.js 22 or newer and npm for browser/KPS tooling
- `curl` for the JavaScript pinned transport
- Docker and OpenSSL only for the local TLS-pinning integration test

Clone with submodules:

```bash
git clone --recurse-submodules https://github.com/obliviouslabs/oblivious_revm_client.git
cd oblivious_revm_client
```

## Trust model

1. First contact policy-checks the GCP workload manifest, then runs
   `tdx_easy_https` with the exact manifest SHA-384 as
   `--expected-gcp-workload-digest`.
2. The verifier returns `attested_tls_pin=sha256//...`.
3. Native HTTPS disables CA-based acceptance and accepts exactly that SPKI for
   the attested domain. A mismatch fails closed and requires re-attestation.
4. Each real account proof is checked against the configured state root. Each
   storage proof is checked against the storage root committed by that account.

The library does **not** run an Ethereum consensus light client. The state root
must come from a trusted block header. A root copied from an untrusted RPC does
not provide end-to-end chain authenticity. See [`SECURITY.md`](SECURITY.md).

## Native example

Initialize the submodule and verify first contact:

```bash
git submodule update --init --recursive
cargo run -p safe-node-revm-cli -- attest | tee verify.out
export SAFE_NODE_TLS_PIN="$(sed -n 's/^attested_tls_pin=//p' verify.out | tail -1)"
```

Run the example:

```bash
cargo run -p safe-node-revm-cli -- run
```

The defaults call `name()` on Sepolia WETH9 at immutable block `11344323`
(`0xad19c3`), using committed bytecode and state root from
[`crates/safe-node-revm/fixtures/sepolia-weth9-11344323.json`](crates/safe-node-revm/fixtures/sepolia-weth9-11344323.json).
The expected result is `Wrapped Ether` and the execution reads slot zero through
the adapter. The demo sets the Sepolia chain ID and block number; applications
whose contracts inspect timestamp, fee, randomness, beneficiary, or gas-limit
fields must configure the full `revm` block environment themselves.

The development endpoint is intentionally present in `.env.example`; its URL
contains a public, rate-limited development key, not a deployment secret. The
live node may return `-32001` while proof nodes are unavailable; retries happen
only on later cadence ticks and stop after at most 10 attempts.

## Why this cover fixture

The default cover target is Sepolia WETH9
`0xfff9976782d46cc05630d1f6ebab18b2324d6b14` at the same immutable block.
Slot zero is non-zero and has a short, known proof. This is preferable to random
accounts/slots, which can enter Safe Node's missing-node recovery path and
create avoidable load. Storage padding repeats the last real slot; cover storage
ticks repeat WETH slot zero. Repetition avoids requiring additional trie paths
from a partially populated proof cache.

Account reads cannot always be padded with storage keys: absent accounts and
accounts with an empty storage trie legitimately have no storage proof path.
The public cadence therefore alternates two fixed classes:

1. account-only `eth_getProof(address, [], block)`;
2. storage `eth_getProof(address, [K fixed-width keys], block)`.

Each tick sends exactly one request. Real work replaces cover work of the same
class. Requests larger than `K` are split across storage ticks; the final chunk
is padded by repeating its last key.

## Bytecode and `BLOCKHASH`

Safe Node currently provides no private `eth_getCode`. Bytecode must be
preloaded by address or code hash. The adapter hashes address-preloaded bytes and
rejects them if they differ from the account proof's `codeHash`; it never falls
back to a public code RPC.

`revm::Database` also requires `block_hash(number)` for the EVM `BLOCKHASH`
opcode. Safe Node exposes no block-header method, so hashes needed by a contract
must be preloaded. Missing hashes return an explicit error. Contracts that do
not execute `BLOCKHASH`, including the example, need no block-hash preload.

## Browser/WASM and KPS

Install/build/test:

```bash
rustup target add wasm32-unknown-unknown
cargo check -p safe-node-revm-wasm --target wasm32-unknown-unknown
cd crates/safe-node-revm-wasm
npm install --include=dev
npm run lint
npm test
# Requires a running Docker daemon, curl, and OpenSSL:
npm run test:pinning
cargo install wasm-pack --version 0.15.0 --locked
wasm-pack build --target web --out-dir pkg
npx playwright install chromium
npm run test:browser
```

The browser cannot block a synchronous `revm::Database` call. `WasmExecutor`
instead returns one cache miss, JavaScript waits for that request to replace a
cover tick, applies the verified proof, and reruns from a clean EVM journal. The
cache survives; execution is capped at 10 attempts.

For the real endpoint, first verify natively and launch the local proxy:

```bash
cd crates/safe-node-revm-wasm
SAFE_NODE_TLS_PIN="$SAFE_NODE_TLS_PIN" \
SAFE_NODE_RPC_URL="$SAFE_NODE_RPC_URL" \
npm run proxy
```

The proxy prints a KPS address of the form `<ip>:<port>:<certhash>`. KPS pins the
proxy's own certificate and encrypts browser-to-proxy streams. The proxy sees
plaintext and separately pins Safe Node's attested SPKI; it does **not** attest
Safe Node to the browser unless the proxy itself is part of the attested
workload.

`npm run test:pinning` builds a minimal Docker HTTPS JSON-RPC server with an
ephemeral self-signed certificate. It proves ordinary WebPKI rejects that
server, the exact SPKI pin succeeds through the forwarding module used by the
production KPS proxy, and a different pin is rejected. No test key is committed;
the container, image, certificate, and private key are removed afterward.

## Tests

```bash
cargo test --workspace
cargo check -p safe-node-revm-wasm --target wasm32-unknown-unknown
(cd crates/safe-node-revm-wasm && npm run lint && npm test)
(cd crates/safe-node-revm-wasm && npm run test:pinning)
```

The env-gated live test additionally requires a fresh attested pin:

```bash
SAFE_NODE_INTEGRATION=1 \
SAFE_NODE_TLS_PIN="$SAFE_NODE_TLS_PIN" \
cargo test -p safe-node-revm --test live_safe_node -- --nocapture
```

Tests cover deterministic ticks, unchanged request count when real work replaces
cover, splitting/padding, scheduled retries and the 10-attempt cap, real Sepolia
MPT fixtures, tamper rejection, native `revm` execution, wasm32 compilation, and
a Chromium/WASM/KPS execution smoke test.

## Privacy caveats

Cadence is maintained only while the worker is explicitly alive. Startup,
shutdown, browser timer throttling, OS scheduling, connection backpressure,
outages, and response sizes remain observable. Slow HTTP calls are dispatched
concurrently so they do not intentionally block later ticks, but this is not a
hard real-time transport. Production applications should choose a cover-traffic
lifetime independent of one EVM execution.

## Contributing and license

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for development checks and
[`SECURITY.md`](SECURITY.md) for vulnerability reporting. This project is
dual-licensed under Apache-2.0 or MIT, at your option.
