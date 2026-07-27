# Security policy and privacy boundaries

## Project status

This project is experimental and has not received an independent security
audit. The only supported version is the current `main` branch.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use
[GitHub private vulnerability reporting](https://github.com/obliviouslabs/oblivious_revm_client/security/advisories/new).
Include reproduction steps, affected revisions, and the expected impact. If
private reporting is unavailable, contact an Oblivious Labs organization owner
and request a private reporting channel. Never include production credentials,
private keys, or sensitive query data in a report.

## Safe Node authentication

The native transport does **not** trust ordinary WebPKI by itself. First contact
runs the pinned `tdx_easy_https` verifier and obtains an SPKI pin. Subsequent
connections accept only that public key, including when the currently served
certificate is self-signed. A mismatch is a hard failure: stop and attest the
new key before sending another private query.

The CLI also compensates for a limitation in the current `--gcp-attestd`
verifier: it validates the image digest and selected environment fields in a
bootstrap workload manifest, hashes that exact manifest, and passes the hash to
the quote verifier as `--expected-gcp-workload-digest`. The quote-verified
manifest must therefore be byte-for-byte identical to the policy-checked one.
The bootstrap fetch is not trusted on its own.

## Proof authentication

Every real response is verified as an Ethereum Merkle-Patricia account proof
against a caller-configured block state root. Every returned storage proof is
then verified against the storage root committed by that account. Merely hashing
the first proof node is not an anchor; the configured state root must come from
a trusted block header or consensus client.

This library does not currently run a consensus light client. Supplying a state
root from an unauthenticated RPC merely moves trust to that RPC.

## Constant-rate limits

While a worker is running, it emits one `eth_getProof` call per scheduled tick.
Real work replaces cover work; retries consume later ticks. Account-only and
fixed-width storage ticks alternate in a public, input-independent pattern.
Slow responses are handled concurrently so they do not intentionally stop the
ticker.

This is best effort, not a hard real-time guarantee. OS scheduling, connection
flow control, outages, browser timer throttling, worker startup, and worker
shutdown remain observable. Keep the worker alive for an application-defined
cover interval rather than stopping it immediately when one execution ends.
Response sizes and failure behavior can also leak information.

## Code and BLOCKHASH gaps

Safe Node currently exposes private `eth_getProof`, not private `eth_getCode` or
block-header lookup. Bytecode and any block hashes needed by the EVM must be
preloaded and are checked against committed hashes. Missing data fails closed;
it is never fetched silently over a leaky public channel.

## KPS browser boundary

KPS authenticates and encrypts the browser-to-proxy stream using the KPS
server's certificate hash. That KPS certificate hash is distinct from Safe
Node's attested SPKI pin.

A normal KPS proxy terminates the KPS stream and can read every query. The proxy
then authenticates Safe Node with the separately attested SPKI pin. A pin
mismatch is latched by the proxy and stops the browser scheduler until a new
proxy is started with a freshly attested pin. Therefore a local proxy is trusted
by the browser user and **does not attest Safe Node to the browser**. Only a
proxy running inside, and included in, the attested workload could make that
stronger claim.
