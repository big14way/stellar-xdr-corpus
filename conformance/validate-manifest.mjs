#!/usr/bin/env node
// Validates corpus/manifest.json against schema/manifest.schema.json.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (path) => JSON.parse(readFileSync(join(root, path), "utf8"));

const ajv = new Ajv2020({ allErrors: true, strict: true, allowUnionTypes: true });
addFormats(ajv);
const validate = ajv.compile(read("schema/manifest.schema.json"));
const manifest = read(process.argv[2] ?? "corpus/manifest.json");

if (!validate(manifest)) {
  for (const error of validate.errors) console.error(`${error.instancePath || "/"}: ${error.message}`);
  process.exit(1);
}
console.log(`manifest is valid: ${manifest.entries.length} entries`);
