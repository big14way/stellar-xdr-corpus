#!/usr/bin/env node
// Conformance runner for @stellar/stellar-sdk.
//
// Decodes every corpus entry with the SDK installed in --sdk-dir, re-encodes it,
// and applies the entry's probe to compare decoded values with the manifest.
//
//   node run.mjs --sdk-dir <dir containing node_modules> [--corpus ../../corpus] [--out result.json]

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

function parseArgs(argv) {
  const args = { corpus: join(here, "..", "..", "corpus") };
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i];
    const value = argv[i + 1];
    if (value === undefined) throw new Error(`missing value for ${key}`);
    if (key === "--sdk-dir") args.sdkDir = resolve(value);
    else if (key === "--corpus") args.corpus = resolve(value);
    else if (key === "--out") args.out = resolve(value);
    else throw new Error(`unknown argument ${key}`);
  }
  if (!args.sdkDir) throw new Error("--sdk-dir is required");
  return args;
}

const args = parseArgs(process.argv.slice(2));
const sdkPackageDir = join(args.sdkDir, "node_modules", "@stellar", "stellar-sdk");
const sdkVersion = JSON.parse(readFileSync(join(sdkPackageDir, "package.json"), "utf8")).version;
const sdk = createRequire(join(args.sdkDir, "index.js"))("@stellar/stellar-sdk");

const manifest = JSON.parse(readFileSync(join(args.corpus, "manifest.json"), "utf8"));

// A probe returns one thunk per expected key. Each thunk is evaluated on its own
// so that one failing helper does not hide the values the others report.
const probes = {
  scval_map(bytes) {
    const scv = sdk.xdr.ScVal.fromXDR(bytes);
    return {
      // v16 exposes union arms as methods, v17 as plain properties.
      raw_entry_count: () => (typeof scv.map === "function" ? scv.map() : scv.map).length,
      native_entry_count: () => {
        const native = sdk.scValToNative(scv);
        return native instanceof Map ? native.size : Object.keys(native).length;
      },
    };
  },

  liquidity_pool_change_trust(bytes, entry) {
    const tx = sdk.TransactionBuilder.fromXDR(
      Buffer.from(bytes).toString("base64"),
      entry.source.network_passphrase,
    );
    const line = () => tx.operations[0].line;
    // Renamed from getLiquidityParameters in v17.
    const params = () =>
      typeof line().getLiquidityPoolParameters === "function"
        ? line().getLiquidityPoolParameters()
        : line().getLiquidityParameters();
    const describe = (asset) => `${asset.getCode()}:${asset.getIssuer()}`;
    return {
      asset_a: () => describe(params().assetA),
      asset_b: () => describe(params().assetB),
      fee: () => params().fee,
      limit: () => stroops(tx.operations[0].limit),
      pool_id: () => hex(sdk.getLiquidityPoolId("constant_product", params())),
      tx_hash: () => hex(tx.hash()),
    };
  },

  muxed_payment(bytes, entry) {
    const tx = sdk.TransactionBuilder.fromXDR(
      Buffer.from(bytes).toString("base64"),
      entry.source.network_passphrase,
    );
    const op = () => tx.operations[0];
    const muxed = (address) => sdk.MuxedAccount.fromAddress(address, "0");
    return {
      source: () => tx.source,
      source_id: () => muxed(tx.source).id(),
      source_base: () => muxed(tx.source).baseAccount().accountId(),
      op_source: () => op().source,
      op_source_id: () => muxed(op().source).id(),
      destination: () => op().destination,
      destination_id: () => muxed(op().destination).id(),
      destination_base: () => muxed(op().destination).baseAccount().accountId(),
      amount_stroops: () => stroops(op().amount),
      tx_hash: () => hex(tx.hash()),
    };
  },
};

// Hashes are Buffers in v16 and Uint8Arrays in v17.
function hex(bytes) {
  return Buffer.from(bytes).toString("hex");
}

// The SDK reports amounts as decimal strings with up to seven places. Convert
// them back to the integer the ledger stores, without going through a float.
function stroops(amount) {
  const match = /^(\d+)(?:\.(\d{1,7}))?$/.exec(amount);
  if (!match) throw new Error(`not a decimal amount: ${amount}`);
  return (BigInt(match[1]) * 10_000_000n + BigInt((match[2] ?? "").padEnd(7, "0"))).toString();
}

function describeError(error) {
  return error instanceof Error ? error.message : String(error);
}

function checkEntry(entry) {
  const result = { id: entry.id, integrity: "ok", roundtrip: "ok", values: {} };
  const bytes = readFileSync(join(args.corpus, entry.file));

  if (createHash("sha256").update(bytes).digest("hex") !== entry.sha256) {
    result.integrity = "sha256 mismatch";
    result.status = "error";
    return result;
  }

  const xdrType = sdk.xdr[entry.xdr_type];
  if (!xdrType) {
    result.roundtrip = "unsupported";
    result.roundtrip_detail = `xdr.${entry.xdr_type} is not defined in this SDK`;
  } else {
    try {
      const reencoded = xdrType.fromXDR(bytes).toXDR();
      if (!Buffer.from(reencoded).equals(bytes)) result.roundtrip = "mismatch";
    } catch (error) {
      result.roundtrip = "threw";
      result.roundtrip_detail = describeError(error);
    }
  }

  const probe = probes[entry.expect.probe];
  const mayRefuse = new Set(entry.expect.may_refuse ?? []);
  let thunks = {};
  let probeError;
  if (probe) {
    try {
      thunks = probe(bytes, entry);
    } catch (error) {
      probeError = describeError(error);
    }
  }

  for (const [key, expected] of Object.entries(entry.expect.values)) {
    const value = { expected };
    if (!probe) {
      value.outcome = "unsupported";
      value.detail = `runner has no probe named ${entry.expect.probe}`;
    } else if (probeError !== undefined) {
      value.outcome = "threw";
      value.detail = probeError;
    } else if (!(key in thunks)) {
      value.outcome = "not_applicable";
      value.detail = "this SDK has no equivalent helper";
    } else {
      try {
        value.actual = thunks[key]();
        value.outcome = value.actual === expected ? "match" : "mismatch";
      } catch (error) {
        value.outcome = mayRefuse.has(key) ? "refused" : "threw";
        value.detail = describeError(error);
      }
    }
    result.values[key] = value;
  }

  const outcomes = Object.values(result.values).map((v) => v.outcome);
  if (result.roundtrip === "mismatch" || outcomes.includes("mismatch")) result.status = "diverged_silent";
  else if (result.roundtrip === "threw" || outcomes.includes("threw")) result.status = "diverged_error";
  else if (result.roundtrip === "unsupported" || outcomes.includes("unsupported")) result.status = "unsupported";
  else result.status = "pass";
  return result;
}

const report = {
  sdk: "js-stellar-sdk",
  package: "@stellar/stellar-sdk",
  version: sdkVersion,
  runtime: `node ${process.version}`,
  manifest_schema_version: manifest.schema_version,
  results: manifest.entries.map(checkEntry),
};

const text = `${JSON.stringify(report, null, 2)}\n`;
if (args.out) writeFileSync(args.out, text);
else process.stdout.write(text);
