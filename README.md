# stellar-xdr-corpus

A shared corpus of rare but valid Stellar ledger data, with a manifest that says what a correct decoder must report for each entry, and runners that check Stellar SDKs against it. JavaScript and Rust runners work today; Go is next.

**Status: early draft.** Four entries (three synthetic, one real testnet ledger), two runners and a divergence matrix work today. The replay harness for indexers, the linter and the hardening guide are not started. See [Roadmap](#roadmap).

## Why

Every application that reads the Stellar ledger decodes XDR. Rare transaction shapes keep breaking decoders and indexers, and each team finds the same bugs on its own. This repository collects those shapes in one place so a bug found once becomes a test every SDK and indexer can run.

## What the corpus already catches

Running the entries through published SDK releases reproduces two known bugs on the releases that had them and passes on the releases that fixed them. The full table is in [`reports/divergence-matrix.md`](reports/divergence-matrix.md).

| Entry | Bug it reproduces | Fails on | Passes on |
|---|---|---|---|
| `change-trust-pool-issuers-strkey-order-reversed` | [js-stellar-sdk#1766](https://github.com/stellar/js-stellar-sdk/pull/1766): a valid liquidity pool trustline cannot be decoded | 16.3.0, 17.2.0 | 16.4.1, 17.2.1 and later |
| `scval-map-keys-collide-as-native` | [js-stellar-sdk#1789](https://github.com/stellar/js-stellar-sdk/issues/1789): `scValToNative` drops map entries without an error | 16.3.0, 16.4.1, 17.2.0, 17.2.1 | 17.3.0, 17.4.0 |

The fourth entry, `testnet-4437357-signed-payload-signer`, is testnet ledger 4437357 exactly as stellar-core emitted it. It contains the CAP-0040 signed-payload signer that halted wallet-backend ingestion ([wallet-backend#729](https://github.com/stellar/wallet-backend/pull/729)). Its expected ledger hash, transaction hash and signer address were checked against Horizon when it was added. All SDK releases tested decode it correctly; it is in the corpus for the indexer replay harness.

## Layout

```
corpus/manifest.json      index of entries and their expected values
corpus/entries/*.xdr      one raw binary XDR value per entry
schema/                   JSON Schema for the manifest
generator/                Rust: builds the synthetic entries, imports ledgers, verifies the corpus
runners/js|rust/          one conformance runner per SDK
conformance/              runs every SDK release in versions.json, writes the matrix
reports/                  the generated divergence matrix
```

## Manifest

Each entry records:

- `id`, `xdr_type`, `file`, `size`, `sha256`
- `caps` and `protocol`: the CAP that introduced or changed the shape, the protocol version it first appeared in, and the version it was captured under
- `synthetic` and `source`: whether the generator built it or it came from a ledger, and where
- `shapes`: tags for the rare patterns it contains
- `expect`: a named probe and the values a correct decoder must report. 64-bit integers are strings so no JSON parser can round them
- `sightings`: public issues where the shape broke something

The format is defined in [`schema/manifest.schema.json`](schema/manifest.schema.json).

## Run it

Requirements: Rust 1.87 or later and Node 20 or later.

```sh
# Verify the corpus: hashes, sizes, round-trip through rs-stellar-xdr,
# and that the synthetic entries rebuild to identical bytes.
cargo run --release -p corpus-generator -- check

# Run every SDK release in conformance/versions.json and rebuild the matrix.
node conformance/run.mjs
```

The generator needs no network access, keys or funds. Synthetic entries are built from fixed labels, so two runs give the same bytes. To build the signed entries for mainnet instead of testnet:

```sh
cargo run --release -p corpus-generator -- generate --network pubnet --out /tmp/corpus-pubnet
```

## Entries from real ledgers

Ledgers come from the public Galexie data lake. Download one batch file, decompress it, and import it. The generator itself never uses the network.

```sh
curl -sO https://aws-public-blockchain.s3.us-east-2.amazonaws.com/v1.1/stellar/ledgers/testnet/2025-12-18/FFBC9DFF--4416000-4479999/FFBC4A92--4437357.xdr.zst
zstd -d FFBC4A92--4437357.xdr.zst
cargo run --release -p corpus-generator -- import-ledger --batch FFBC4A92--4437357.xdr --id testnet-4437357-signed-payload-signer
```

`import-ledger` prints the SHA-256 of the extracted ledger. The entry is then described in `generator/src/captured.rs` with that hash and its expected values. On every run the generator checks the committed file against the pinned hash and re-derives the expected values from the bytes.

## How a runner judges an entry

1. Check the file against the manifest's SHA-256.
2. Decode it as `xdr_type` and re-encode it. The bytes must be identical.
3. Apply the entry's probe: read the values the SDK reports through its public API and compare each with the manifest.

A returned value that differs is reported as **WRONG VALUE**. An error on valid ledger data is reported as **ERROR**. Where an SDK's native type cannot hold a value, the manifest can list that value under `may_refuse`, and an explicit error then counts as a pass. Returning a different value silently never passes.

## Roadmap

- Go SDK runner
- More entries from real testnet and mainnet ledgers, and from stellar-core's golden `LedgerCloseMeta` files
- Per-CAP coverage report
- Replay harness that feeds the corpus to an indexer through a documented adapter
- Linter for the three common indexer mistakes
- Indexer-hardening guide

## License

Apache-2.0. See [LICENSE](LICENSE).
