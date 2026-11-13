// Unit tests for the parts of the harness that need no indexer or database.
//
//   node --test harness/harness.test.mjs

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { zstdDecompressSync } from "node:zlib";

import { BUCKET, lakeObjects, ledgerBatch, ledgerObjectKey, startLake } from "./lake.mjs";
import { decodeStrkey, encodeStrkey } from "./strkey.mjs";

const corpus = join(dirname(fileURLToPath(import.meta.url)), "..", "corpus");
const manifest = JSON.parse(readFileSync(join(corpus, "manifest.json"), "utf8"));
const ledgerEntry = manifest.entries.find((e) => e.id === "testnet-4437357-signed-payload-signer");

test("ledger object key matches the key in the public testnet lake", () => {
  // The entry records the URL it was downloaded from; the lake must name the
  // same ledger the same way.
  assert.ok(ledgerEntry.source.retrieved_from.endsWith(`/${ledgerObjectKey(4437357)}`));
  assert.equal(ledgerObjectKey(4437357), "FFBC9DFF--4416000-4479999/FFBC4A92--4437357.xdr.zst");
  assert.equal(ledgerObjectKey(2), "FFFFFFFF--0-63999/FFFFFFFD--2.xdr.zst");
  assert.equal(ledgerObjectKey(64000), "FFFF05FF--64000-127999/FFFF05FF--64000.xdr.zst");
});

test("ledger batch wraps one ledger", () => {
  const batch = ledgerBatch(7, Buffer.from([0xaa, 0xbb, 0xcc, 0xdd]));
  assert.equal(batch.toString("hex"), "000000070000000700000001aabbccdd");
});

test("strkey round-trips a signed-payload address and rejects a bad checksum", () => {
  const address = ledgerEntry.expect.values.signers_in_meta;
  const raw = decodeStrkey(address);
  assert.equal(raw[0], 15 << 3); // version byte of a P address
  assert.equal(encodeStrkey(raw), address);
  assert.throws(() => decodeStrkey(`${address.slice(0, -1)}A`), /checksum/);
});

test("strkey encodes an account address", () => {
  // GAAA...WHF is the all-zero ed25519 key.
  const zeroAccount = Buffer.concat([Buffer.from([6 << 3]), Buffer.alloc(32)]);
  assert.equal(encodeStrkey(zeroAccount), "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF");
});

test("lake serves the manifest, the ledger and a listing over the S3 API", async () => {
  const ledgerCloseMeta = readFileSync(join(corpus, ledgerEntry.file));
  const key = `${ledgerEntry.id}/${ledgerObjectKey(ledgerEntry.source.ledger_seq)}`;
  const lake = await startLake(
    lakeObjects(ledgerEntry.id, {
      ledgerSeq: ledgerEntry.source.ledger_seq,
      networkPassphrase: ledgerEntry.source.network_passphrase,
      ledgerCloseMeta,
    }),
  );
  try {
    const config = await fetch(`${lake.url}/${BUCKET}/${ledgerEntry.id}/.config.json`);
    assert.equal(config.status, 200);
    assert.deepEqual(await config.json(), {
      networkPassphrase: "Test SDF Network ; September 2015",
      version: "1.0",
      compression: "zstd",
      ledgersPerBatch: 1,
      batchesPerPartition: 64000,
    });

    assert.equal(lake.served(key), false);
    const object = await fetch(`${lake.url}/${BUCKET}/${key}`);
    assert.equal(object.status, 200);
    const batch = zstdDecompressSync(Buffer.from(await object.arrayBuffer()));
    assert.ok(batch.subarray(12).equals(ledgerCloseMeta));
    assert.equal(lake.served(key), true);

    const listing = await (await fetch(`${lake.url}/${BUCKET}?list-type=2&prefix=${ledgerEntry.id}%2F&max-keys=1`)).text();
    assert.match(listing, /<KeyCount>1<\/KeyCount>/);
    assert.match(listing, /<IsTruncated>true<\/IsTruncated>/);

    const missing = await fetch(`${lake.url}/${BUCKET}/${ledgerEntry.id}/nope`);
    assert.equal(missing.status, 404);
    assert.match(await missing.text(), /<Code>NoSuchKey<\/Code>/);

    const write = await fetch(`${lake.url}/${BUCKET}/${key}`, { method: "PUT", body: "x" });
    assert.equal(write.status, 405);
  } finally {
    await lake.close();
  }
});
