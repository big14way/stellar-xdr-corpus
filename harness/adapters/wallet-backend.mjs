// Reference adapter: stellar/wallet-backend.
//
// The indexer is built from an unmodified checkout and run in live ingestion
// mode with its normal data-lake settings, pointed at the corpus lake. It is
// started as an instance that has already ingested up to the ledger before the
// corpus ledger, so the corpus ledger is the next one it must ingest.

import { execFile, spawn } from "node:child_process";
import { createWriteStream, existsSync, mkdirSync, readFileSync } from "node:fs";
import { createServer } from "node:net";
import { join } from "node:path";
import { promisify } from "node:util";

import { decodeStrkey, encodeStrkey } from "../strkey.mjs";

const run = promisify(execFile);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export const name = "wallet-backend";
export const repository = "https://github.com/stellar/wallet-backend";

// The database wallet-backend's own docker-compose.yaml starts.
export const database = {
  image: "timescale/timescaledb:2.28.2-pg17",
  args: ["postgres", "-c", "timescaledb.enable_chunk_skipping=on", "-c", "timescaledb.enable_sparse_index_bloom=on"],
};

// How long the indexer gets to move past the ledger. Its own retry ladder for a
// failed ledger takes about 15 seconds before it gives up.
const INGEST_TIMEOUT_MS = 90_000;

// Builds the indexer at `commit` and returns what replay() needs to run it.
export async function build(commit, { cacheDir, log }) {
  const binary = join(cacheDir, "bin", `wallet-backend-${commit}`);
  if (existsSync(binary)) return { binary };

  const source = join(cacheDir, "wallet-backend");
  if (!existsSync(join(source, ".git"))) {
    log(`cloning ${repository}`);
    await run("git", ["clone", "--quiet", "--filter=blob:none", "--no-checkout", repository, source]);
  }
  const git = (...args) => run("git", ["-C", source, ...args]);
  try {
    await git("cat-file", "-e", `${commit}^{commit}`);
  } catch {
    await git("fetch", "--quiet", "origin");
  }
  await git("checkout", "--quiet", "--detach", "--force", commit);
  log(`building wallet-backend ${commit.slice(0, 7)}`);
  mkdirSync(join(cacheDir, "bin"), { recursive: true });
  await run("go", ["build", "-o", binary, "."], { cwd: source, maxBuffer: 64 * 1024 * 1024 });
  return { binary };
}

async function freePort() {
  const server = createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return port;
}

// The indexer gets a fixed environment and nothing from the caller's, so it
// cannot pick up real cloud credentials or settings from this machine.
function indexerEnv(extra) {
  return {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    AWS_ACCESS_KEY_ID: "replay",
    AWS_SECRET_ACCESS_KEY: "replay",
    AWS_EC2_METADATA_DISABLED: "true",
    AWS_CONFIG_FILE: "/dev/null",
    AWS_SHARED_CREDENTIALS_FILE: "/dev/null",
    ...extra,
  };
}

// Serves `entry` to the indexer and reports what it did with it:
//   { ingested: false, reason }   it did not get past the ledger
//   { ingested: true, values }    it did; `values` are read back from its
//                                 database, keyed like the manifest's expect.values
export async function replay({ binary }, entry, { lake, db, databaseName, logFile }) {
  const ledgerSeq = entry.source.ledger_seq;
  const passphrase = entry.source.network_passphrase;
  const databaseUrl = db.url(databaseName);

  await db.sql("postgres", `CREATE DATABASE ${databaseName}`);
  await db.sql(databaseName, "CREATE EXTENSION IF NOT EXISTS timescaledb");

  const out = createWriteStream(logFile);
  const finished = new Promise((resolve) => out.on("finish", resolve));

  try {
    await run(binary, ["migrate", "up"], { env: indexerEnv({ DATABASE_URL: databaseUrl }), maxBuffer: 64 * 1024 * 1024 });

    // The state of an instance whose last ingested ledger is the one before.
    await db.sql(
      databaseName,
      `INSERT INTO ingest_store (key, value) VALUES ('latest_ingest_ledger', '${ledgerSeq - 1}'), ('oldest_ingest_ledger', '${ledgerSeq - 1}')`,
    );

    const child = spawn(binary, ["ingest"], {
      stdio: ["ignore", "pipe", "pipe"],
      env: indexerEnv({
        DATABASE_URL: databaseUrl,
        INGESTION_MODE: "live",
        NETWORK: passphrase.startsWith("Public") ? "mainnet" : "testnet",
        NETWORK_PASSPHRASE: passphrase,
        LEDGER_BACKEND_TYPE: "datastore",
        DATASTORE_BUCKET_PATH: lake.bucketPath,
        DATASTORE_ENDPOINT_URL: lake.url,
        DATASTORE_REGION: "us-east-1",
        DATASTORE_RETRY_WAIT: "1s",
        RPC_URL: `${lake.url}/rpc`,
        ARCHIVE_URL: `${lake.url}/archive`,
        INGEST_SERVER_PORT: String(await freePort()),
        STELLAR_ENVIRONMENT: "development",
        LOG_LEVEL: "INFO",
      }),
    });
    child.stdout.pipe(out, { end: false });
    child.stderr.pipe(out, { end: false });
    // "close" fires after the process has exited and its output has drained.
    let exited = false;
    const exit = new Promise((resolve) => child.once("close", () => { exited = true; resolve(); }));

    const cursor = async () =>
      Number(await db.sql(databaseName, "SELECT value FROM ingest_store WHERE key = 'latest_ingest_ledger'"));

    const deadline = Date.now() + INGEST_TIMEOUT_MS;
    let latest = await cursor();
    while (latest < ledgerSeq && !exited && Date.now() < deadline) {
      await sleep(250);
      latest = await cursor();
    }
    if (!exited) {
      child.kill("SIGTERM");
      await Promise.race([exit, sleep(15_000)]);
      if (!exited) {
        child.kill("SIGKILL");
        await exit;
      }
    }
    latest = await cursor();

    if (!lake.served(lake.ledgerKey)) {
      throw new Error(`wallet-backend never fetched the ledger from the lake; see ${logFile}`);
    }
    if (latest < ledgerSeq) {
      out.end();
      await finished;
      return { ingested: false, reason: haltReason(readFileSync(logFile, "utf8")) };
    }
    return { ingested: true, values: await probes[entry.expect.probe]?.(entry, { db, databaseName, ledgerSeq, latest }) ?? {} };
  } finally {
    out.end();
    await finished;
  }
}

// The indexer's own explanation for not persisting the ledger: the innermost
// part of its last error line, which names the row it could not store.
// Timestamps, attempt counters and backoff times are left out so the report is
// the same on every run.
function haltReason(log) {
  const errors = log.split("\n").filter((line) => /level=(error|fatal|warning)/.test(line));
  for (const line of errors.reverse()) {
    const message = /msg="((?:[^"\\]|\\.)*)"/.exec(line)?.[1]?.replace(/\\"/g, '"');
    if (!message) continue;
    const cause = /((?:decoding )?stellar address \S+ has .*?)(?:\s*\(SQLSTATE|, retrying|$)/.exec(message);
    return cause ? cause[1] : message.replace(/\(attempt \d+\/\d+\)/g, "").replace(/, retrying in [\d.a-zµ]+\.*/g, "").trim();
  }
  return "no error was logged";
}

// One probe per manifest probe name. Each returns the values wallet-backend
// stored, under the same keys the manifest uses, so the runner can compare them.
const probes = {
  async ledger_signed_payload_signers(entry, { db, databaseName, ledgerSeq, latest }) {
    const rows = async (text) => (await db.sql(databaseName, text)).split("\n").filter(Boolean);
    const signedPayloadVersionByte = decodeStrkey(entry.expect.values.signers_in_meta.split(",")[0])[0];

    // Every signer key stored for this ledger whose version byte says it is a
    // signed payload, re-encoded as the address those bytes spell.
    const stored = await rows(
      `SELECT DISTINCT encode(signer_account_id, 'hex') FROM state_changes
        WHERE ledger_number = ${ledgerSeq} AND signer_account_id IS NOT NULL
          AND get_byte(signer_account_id, 0) = ${signedPayloadVersionByte}`,
    );
    return {
      ledger_seq: latest,
      tx_count: Number(await db.sql(databaseName, `SELECT count(*) FROM transactions WHERE ledger_number = ${ledgerSeq}`)),
      signers_in_meta: stored.map((hex) => encodeStrkey(Buffer.from(hex, "hex"))).sort().join(","),
    };
  },
};
