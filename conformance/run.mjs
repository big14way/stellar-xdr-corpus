#!/usr/bin/env node
// Runs the corpus through every SDK version listed in versions.json and writes
// the divergence matrix.
//
//   node conformance/run.mjs [--only js|go|rust]
//
// Reports are deterministic: they contain no timestamps or machine details, so
// CI can regenerate them and fail when they differ from what is committed.

import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const corpus = join(root, "corpus");
const cache = join(root, ".sdk-cache");
const resultsDir = join(root, "results");
const reportsDir = join(root, "reports");
const versions = JSON.parse(readFileSync(join(root, "conformance", "versions.json"), "utf8"));
const manifest = JSON.parse(readFileSync(join(corpus, "manifest.json"), "utf8"));

const onlyIndex = process.argv.indexOf("--only");
const only = onlyIndex === -1 ? null : process.argv[onlyIndex + 1];
const wants = (name) => only === null || only === name;

function sh(command, args, options = {}) {
  return execFileSync(command, args, { stdio: ["ignore", "pipe", "inherit"], encoding: "utf8", ...options });
}

function resultPath(sdk, version) {
  return join(resultsDir, `${sdk}@${version}.json`);
}

function runJs(version) {
  const dir = join(cache, "js", version);
  const installed = join(dir, "node_modules", "@stellar", "stellar-sdk", "package.json");
  if (!existsSync(installed)) {
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "package.json"), '{"private":true}\n');
    sh("npm", ["install", "--silent", "--no-audit", "--no-fund", "--ignore-scripts", "--save-exact",
      `@stellar/stellar-sdk@${version}`], { cwd: dir });
  }
  sh("node", [join(root, "runners", "js", "run.mjs"), "--sdk-dir", dir, "--corpus", corpus,
    "--out", resultPath("js-stellar-sdk", version)]);
}

function runGo(version) {
  // Each version gets its own module so the pinned go.mod in runners/go is untouched.
  const dir = join(cache, "go", version);
  mkdirSync(dir, { recursive: true });
  copyFileSync(join(root, "runners", "go", "main.go"), join(dir, "main.go"));
  if (!existsSync(join(dir, "go.sum"))) {
    writeFileSync(join(dir, "go.mod"),
      `module conformance-go\n\ngo 1.25.0\n\nrequire github.com/stellar/go-stellar-sdk ${version}\n`);
    sh("go", ["mod", "tidy"], { cwd: dir });
  }
  sh("go", ["run", ".", "--corpus", corpus, "--out", resultPath("go-stellar-sdk", version)], { cwd: dir });
}

function runRust() {
  const out = sh("cargo", ["run", "--quiet", "--release", "-p", "conformance-rust", "--", "--corpus", corpus],
    { cwd: root });
  const version = JSON.parse(out).version;
  if (version !== versions["rs-stellar-xdr"][0]) {
    throw new Error(`Cargo pins stellar-xdr ${version}, versions.json says ${versions["rs-stellar-xdr"][0]}`);
  }
  writeFileSync(resultPath("rs-stellar-xdr", version), out);
}

rmSync(resultsDir, { recursive: true, force: true });
mkdirSync(resultsDir, { recursive: true });
mkdirSync(reportsDir, { recursive: true });

if (wants("js")) for (const v of versions["js-stellar-sdk"]) runJs(v);
if (wants("go")) for (const v of versions["go-stellar-sdk"]) runGo(v);
if (wants("rust")) runRust();

// ---- Build the matrix ------------------------------------------------------

const columns = [];
for (const sdk of ["js-stellar-sdk", "go-stellar-sdk", "rs-stellar-xdr"]) {
  for (const version of versions[sdk]) {
    const path = resultPath(sdk, version);
    if (!existsSync(path)) continue;
    const report = JSON.parse(readFileSync(path, "utf8"));
    if (report.sdk !== sdk || report.version !== version) {
      throw new Error(`${path} reports ${report.sdk}@${report.version}`);
    }
    columns.push({ sdk, version, results: new Map(report.results.map((r) => [r.id, r])) });
  }
}

const label = {
  pass: "pass",
  diverged_silent: "WRONG VALUE",
  diverged_error: "ERROR",
  unsupported: "not run",
  error: "corpus error",
};

const matrix = { schema_version: manifest.schema_version, columns: [], entries: [] };
matrix.columns = columns.map((c) => `${c.sdk}@${c.version}`);
const findings = [];

for (const entry of manifest.entries) {
  const row = { id: entry.id, caps: entry.caps, statuses: {} };
  for (const column of columns) {
    const name = `${column.sdk}@${column.version}`;
    const result = column.results.get(entry.id);
    if (!result) throw new Error(`${name} has no result for ${entry.id}`);
    row.statuses[name] = result.status;
    if (result.status === "pass") continue;

    const problems = [];
    if (result.roundtrip !== "ok") {
      problems.push({ what: "re-encode", outcome: result.roundtrip, detail: result.roundtrip_detail });
    }
    for (const [key, value] of Object.entries(result.values)) {
      if (["match", "refused", "not_applicable"].includes(value.outcome)) continue;
      problems.push({ what: key, outcome: value.outcome, expected: value.expected, actual: value.actual, detail: value.detail });
    }
    findings.push({ entry: entry.id, sdk: column.sdk, version: column.version, status: result.status, sightings: entry.sightings ?? [], problems });
  }
  matrix.entries.push(row);
}
matrix.findings = findings;
writeFileSync(join(reportsDir, "divergence-matrix.json"), `${JSON.stringify(matrix, null, 2)}\n`);

// Markdown: one table per SDK so the columns stay readable.
const lines = [
  "# Divergence matrix",
  "",
  "Generated by `node conformance/run.mjs`. Do not edit by hand.",
  "",
  "Each cell is the result of decoding one corpus entry with one SDK release, re-encoding it, and comparing the values the SDK reports with the manifest.",
  "",
  "- **pass**: bytes re-encode identically and every reported value matches.",
  "- **WRONG VALUE**: the SDK returned a value that differs from the ledger, without an error.",
  "- **ERROR**: the SDK raised an error on valid ledger data.",
  "",
];
for (const sdk of ["js-stellar-sdk", "go-stellar-sdk", "rs-stellar-xdr"]) {
  const own = columns.filter((c) => c.sdk === sdk);
  if (own.length === 0) continue;
  lines.push(`## ${sdk}`, "");
  lines.push(`| Entry | CAP | ${own.map((c) => c.version).join(" | ")} |`);
  lines.push(`|---|---|${own.map(() => "---").join("|")}|`);
  for (const entry of manifest.entries) {
    const cells = own.map((c) => label[c.results.get(entry.id).status]);
    lines.push(`| \`${entry.id}\` | ${entry.caps.join(", ")} | ${cells.join(" | ")} |`);
  }
  lines.push("");
}

lines.push("## Findings", "");
if (findings.length === 0) lines.push("None.", "");
// Group identical problems across versions of the same SDK.
const grouped = new Map();
for (const finding of findings) {
  const key = JSON.stringify([finding.entry, finding.sdk, finding.status, finding.problems]);
  if (!grouped.has(key)) grouped.set(key, { ...finding, versions: [] });
  grouped.get(key).versions.push(finding.version);
}
for (const group of grouped.values()) {
  lines.push(`### \`${group.entry}\` in ${group.sdk} ${group.versions.join(", ")}`, "");
  lines.push(`Result: **${label[group.status]}**`, "");
  // Collapse values that all failed with the same message into one line.
  const byMessage = new Map();
  for (const problem of group.problems) {
    const message = problem.outcome === "mismatch"
      ? `expected \`${JSON.stringify(problem.expected)}\`, got \`${JSON.stringify(problem.actual)}\``
      : `${problem.outcome}: ${problem.detail ?? ""}`.trim();
    if (!byMessage.has(message)) byMessage.set(message, []);
    byMessage.get(message).push(problem.what);
  }
  for (const [message, whats] of byMessage) {
    lines.push(`- ${whats.map((w) => `\`${w}\``).join(", ")}: ${message}`);
  }
  if (group.sightings.length > 0) lines.push("", `Known upstream: ${group.sightings.join(", ")}`);
  lines.push("");
}
writeFileSync(join(reportsDir, "divergence-matrix.md"), `${lines.join("\n").trimEnd()}\n`);

const counts = {};
for (const row of matrix.entries) for (const s of Object.values(row.statuses)) counts[s] = (counts[s] ?? 0) + 1;
console.log(`${manifest.entries.length} entries x ${columns.length} SDK releases:`, counts);
