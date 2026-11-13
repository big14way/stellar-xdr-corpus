#!/usr/bin/env node
// Replays every corpus ledger against every indexer commit listed in
// indexers.json and writes the replay matrix.
//
//   node harness/run.mjs [--indexer <name>] [--commit <hash prefix>] [--entry <id>]
//
// With any filter, the chosen replays are run and summarised but reports/ is
// not written. Needs Docker, Go and git.
//
// Reports are deterministic: they contain no timestamps or machine details, so
// CI can regenerate them and fail when they differ from what is committed.

import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { startDatabase } from "./database.mjs";
import { BUCKET, lakeObjects, ledgerObjectKey, startLake } from "./lake.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const corpus = join(root, "corpus");
const cacheDir = join(root, ".indexer-cache");
const logsDir = join(root, "results", "replay");
const reportsDir = join(root, "reports");
const manifest = JSON.parse(readFileSync(join(corpus, "manifest.json"), "utf8"));
const indexers = JSON.parse(readFileSync(join(here, "indexers.json"), "utf8"));

function option(name) {
  const index = process.argv.indexOf(name);
  if (index === -1) return null;
  const value = process.argv[index + 1];
  if (value === undefined) throw new Error(`missing value for ${name}`);
  return value;
}
const only = { indexer: option("--indexer"), commit: option("--commit"), entry: option("--entry") };
const partial = Object.values(only).some((value) => value !== null);
const log = (message) => console.error(message);

// An entry can be replayed when it is a whole ledger with a known sequence
// number and network. Transaction and value entries are covered by the SDK
// conformance runners instead.
const replayable = (entry) =>
  entry.xdr_type === "LedgerCloseMeta" &&
  Number.isInteger(entry.source.ledger_seq) &&
  typeof entry.source.network_passphrase === "string";

const entries = manifest.entries.filter((entry) => replayable(entry) && (only.entry === null || entry.id === only.entry));
if (entries.length === 0) throw new Error("no corpus entry to replay");

// One lake per entry, all on one server.
const objects = new Map();
for (const entry of entries) {
  const built = lakeObjects(entry.id, {
    ledgerSeq: entry.source.ledger_seq,
    networkPassphrase: entry.source.network_passphrase,
    ledgerCloseMeta: readFileSync(join(corpus, entry.file)),
  });
  for (const [key, body] of built) objects.set(key, body);
}

const label = { pass: "pass", wrong_value: "WRONG VALUE", halted: "HALT" };

function judge(entry, outcome) {
  if (!outcome.ingested) return { status: "halted", reason: outcome.reason, problems: [] };
  const problems = [];
  for (const [key, actual] of Object.entries(outcome.values)) {
    const expected = entry.expect.values[key];
    if (expected === undefined) throw new Error(`adapter reported ${key}, which ${entry.id} does not expect`);
    if (actual !== expected) problems.push({ what: key, expected, actual });
  }
  const checked = Object.keys(outcome.values).sort();
  if (checked.length === 0) throw new Error(`adapter has no probe for ${entry.expect.probe}, so ${entry.id} cannot be judged`);
  return { status: problems.length > 0 ? "wrong_value" : "pass", checked, problems };
}

rmSync(logsDir, { recursive: true, force: true });
const columns = [];
const results = [];
let databases = 0;

for (const [indexerName, config] of Object.entries(indexers)) {
  if (only.indexer !== null && only.indexer !== indexerName) continue;
  const commits = config.commits.filter((c) => only.commit === null || c.commit.startsWith(only.commit));
  if (commits.length === 0) continue;
  const adapter = await import(join(here, "adapters", config.adapter));

  // Build everything first: a failed build should not leave a database running.
  const builds = new Map();
  for (const { commit } of commits) builds.set(commit, await adapter.build(commit, { cacheDir, log }));

  const lake = await startLake(objects);
  const db = await startDatabase(adapter.database);
  try {
    for (const { commit, label: commitLabel } of commits) {
      const column = { indexer: indexerName, repository: adapter.repository, commit, label: commitLabel };
      columns.push(column);
      for (const entry of entries) {
        const ledgerKey = `${entry.id}/${ledgerObjectKey(entry.source.ledger_seq)}`;
        const requestsBefore = lake.requests.length;
        mkdirSync(join(logsDir, indexerName, commit.slice(0, 7)), { recursive: true });
        log(`replaying ${entry.id} against ${indexerName} ${commit.slice(0, 7)}`);
        const outcome = await adapter.replay(builds.get(commit), entry, {
          db,
          databaseName: `replay_${(databases += 1)}`,
          logFile: join(logsDir, indexerName, commit.slice(0, 7), `${entry.id}.log`),
          lake: {
            url: lake.url,
            bucketPath: `${BUCKET}/${entry.id}`,
            ledgerKey,
            // Only requests made during this replay count.
            served: (key) =>
              lake.requests.slice(requestsBefore).some((r) => r.method === "GET" && r.status === 200 && r.path === `/${BUCKET}/${key}`),
          },
        });
        results.push({ entry: entry.id, indexer: indexerName, commit, ...judge(entry, outcome) });
      }
    }
  } finally {
    await db.stop();
    await lake.close();
  }
}

for (const result of results) {
  console.log(`${result.indexer}@${result.commit.slice(0, 7)} ${result.entry}: ${label[result.status]}`);
}
if (partial) {
  console.log("partial run: reports/ left untouched");
  process.exit(0);
}

// ---- Write the matrix -------------------------------------------------------

const resultFor = (column, entry) =>
  results.find((r) => r.indexer === column.indexer && r.commit === column.commit && r.entry === entry.id);

const matrix = {
  schema_version: manifest.schema_version,
  columns: columns.map(({ indexer, repository, commit, label: commitLabel }) => ({ indexer, repository, commit, label: commitLabel })),
  entries: entries.map((entry) => ({
    id: entry.id,
    caps: entry.caps,
    statuses: Object.fromEntries(columns.map((c) => [`${c.indexer}@${c.commit}`, resultFor(c, entry).status])),
  })),
  findings: results
    .filter((r) => r.status !== "pass")
    .map((r) => ({ ...r, sightings: manifest.entries.find((e) => e.id === r.entry).sightings ?? [] })),
};
mkdirSync(reportsDir, { recursive: true });
writeFileSync(join(reportsDir, "replay-matrix.json"), `${JSON.stringify(matrix, null, 2)}\n`);

const lines = [
  "# Replay matrix",
  "",
  "Generated by `node harness/run.mjs`. Do not edit by hand.",
  "",
  "Each cell is the result of serving one corpus ledger to one commit of an indexer, built from an unmodified checkout, and reading back what it stored. The ledger is served in the Galexie data-lake layout and is the next ledger the indexer has to ingest.",
  "",
  "- **pass**: the indexer ingested the ledger and every value read back from its database matches the manifest.",
  "- **WRONG VALUE**: the indexer ingested the ledger but stored a value that differs from the ledger, without an error.",
  "- **HALT**: the indexer did not get past the ledger.",
  "",
];
for (const indexerName of new Set(columns.map((c) => c.indexer))) {
  const own = columns.filter((c) => c.indexer === indexerName);
  lines.push(`## ${indexerName}`, "");
  lines.push(`| Entry | CAP | ${own.map((c) => `\`${c.commit.slice(0, 7)}\`<br/>${c.label}`).join(" | ")} |`);
  lines.push(`|---|---|${own.map(() => "---").join("|")}|`);
  for (const entry of entries) {
    lines.push(`| \`${entry.id}\` | ${entry.caps.join(", ")} | ${own.map((c) => label[resultFor(c, entry).status]).join(" | ")} |`);
  }
  lines.push("", "Commits:", "");
  for (const c of own) lines.push(`- [\`${c.commit.slice(0, 7)}\`](${c.repository}/commit/${c.commit}): ${c.label}`);
  lines.push("");
}

lines.push("## Findings", "");
if (matrix.findings.length === 0) lines.push("None.", "");
for (const finding of matrix.findings) {
  lines.push(`### \`${finding.entry}\` in ${finding.indexer} \`${finding.commit.slice(0, 7)}\``, "");
  lines.push(`Result: **${label[finding.status]}**`, "");
  if (finding.status === "halted") lines.push(`The indexer's own error: \`${finding.reason}\``);
  for (const problem of finding.problems) {
    lines.push(`- \`${problem.what}\`: expected \`${JSON.stringify(problem.expected)}\`, got \`${JSON.stringify(problem.actual)}\``);
  }
  if (finding.sightings.length > 0) lines.push("", `Known upstream: ${finding.sightings.join(", ")}`);
  lines.push("");
}
writeFileSync(join(reportsDir, "replay-matrix.md"), `${lines.join("\n").trimEnd()}\n`);
