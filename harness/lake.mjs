// Serves corpus ledgers the way a Galexie data lake does.
//
// Each corpus entry of type LedgerCloseMeta becomes its own lake under
// <bucket>/<entry id>/, holding a manifest and one ledger file in the layout
// Galexie writes. The server speaks the read-only part of the S3 API that
// go-stellar-sdk's datastore client uses, so an indexer is pointed at it with
// its normal data-lake settings and no code changes.

import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { zstdCompressSync } from "node:zlib";

export const BUCKET = "corpus";

// One ledger per file and 64,000 files per partition, as in the public lakes.
export const LEDGERS_PER_FILE = 1;
export const FILES_PER_PARTITION = 64000;

const MAX_UINT32 = 0xffffffff;
const hex8 = (n) => n.toString(16).toUpperCase().padStart(8, "0");

// The object key Galexie gives a ledger. File names count down from 2^32-1 so
// that the newest ledger lists first.
export function ledgerObjectKey(ledgerSeq) {
  const partitionSize = LEDGERS_PER_FILE * FILES_PER_PARTITION;
  const partitionStart = Math.floor(ledgerSeq / partitionSize) * partitionSize;
  const partitionEnd = Math.min(partitionStart + partitionSize - 1, MAX_UINT32);
  const partition = `${hex8(MAX_UINT32 - partitionStart)}--${partitionStart}-${partitionEnd}`;
  return `${partition}/${hex8(MAX_UINT32 - ledgerSeq)}--${ledgerSeq}.xdr.zst`;
}

// XDR LedgerCloseMetaBatch holding exactly one ledger:
//   uint32 startSequence, uint32 endSequence, LedgerCloseMeta ledgerCloseMetas<>
export function ledgerBatch(ledgerSeq, ledgerCloseMeta) {
  const head = Buffer.alloc(12);
  head.writeUInt32BE(ledgerSeq, 0);
  head.writeUInt32BE(ledgerSeq, 4);
  head.writeUInt32BE(1, 8);
  return Buffer.concat([head, ledgerCloseMeta]);
}

export function lakeManifest(networkPassphrase) {
  return {
    networkPassphrase,
    version: "1.0",
    compression: "zstd",
    ledgersPerBatch: LEDGERS_PER_FILE,
    batchesPerPartition: FILES_PER_PARTITION,
  };
}

// The objects of one entry's lake, keyed by their path inside the bucket.
export function lakeObjects(prefix, { ledgerSeq, networkPassphrase, ledgerCloseMeta }) {
  return new Map([
    [`${prefix}/.config.json`, Buffer.from(JSON.stringify(lakeManifest(networkPassphrase)))],
    [`${prefix}/${ledgerObjectKey(ledgerSeq)}`, zstdCompressSync(ledgerBatch(ledgerSeq, ledgerCloseMeta))],
  ]);
}

const xmlEscape = (text) =>
  text.replace(/[<>&'"]/g, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", "'": "&apos;", '"': "&quot;" })[c]);

function s3Error(code, message, extra = "") {
  return `<?xml version="1.0" encoding="UTF-8"?>\n<Error><Code>${code}</Code><Message>${xmlEscape(message)}</Message>${extra}</Error>`;
}

// Starts the server on a free local port. `objects` maps keys to Buffers.
// Every request is recorded in `requests` so a replay can tell whether the
// indexer really fetched the ledger.
export async function startLake(objects) {
  const keys = [...objects.keys()].sort();
  const requests = [];
  const lastModified = new Date(Date.UTC(2020, 0, 1));

  const server = createServer((req, res) => {
    const url = new URL(req.url, "http://lake");
    const segments = url.pathname.split("/").filter(Boolean).map(decodeURIComponent);
    const send = (status, body, type = "application/xml") => {
      requests.push({ method: req.method, path: url.pathname, query: url.search, status });
      res.writeHead(status, { "Content-Type": type, "Content-Length": Buffer.byteLength(body) });
      res.end(req.method === "HEAD" ? undefined : body);
    };

    // The indexer is also given this server as its RPC and history archive
    // URLs. A replay must not depend on either, so both answer with errors.
    if (segments[0] === "rpc") {
      req.resume();
      return send(200, JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32601, message: "Method not found" } }), "application/json");
    }
    if (segments[0] !== BUCKET) {
      return send(404, s3Error("NoSuchBucket", "The specified bucket does not exist."));
    }
    if (req.method !== "GET" && req.method !== "HEAD") {
      return send(405, s3Error("MethodNotAllowed", "This lake is read-only."));
    }

    // ListObjectsV2
    if (segments.length === 1) {
      const prefix = url.searchParams.get("prefix") ?? "";
      const after = url.searchParams.get("continuation-token") ?? url.searchParams.get("start-after") ?? "";
      const maxKeys = Math.min(Number(url.searchParams.get("max-keys") ?? 1000), 1000);
      const matching = keys.filter((key) => key.startsWith(prefix) && key > after);
      const page = matching.slice(0, maxKeys);
      const truncated = matching.length > page.length;
      const contents = page
        .map((key) => {
          const body = objects.get(key);
          const etag = createHash("md5").update(body).digest("hex");
          return `<Contents><Key>${xmlEscape(key)}</Key><LastModified>${lastModified.toISOString()}</LastModified><ETag>&quot;${etag}&quot;</ETag><Size>${body.length}</Size><StorageClass>STANDARD</StorageClass></Contents>`;
        })
        .join("");
      return send(
        200,
        `<?xml version="1.0" encoding="UTF-8"?>\n<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>${BUCKET}</Name><Prefix>${xmlEscape(prefix)}</Prefix><KeyCount>${page.length}</KeyCount><MaxKeys>${maxKeys}</MaxKeys><IsTruncated>${truncated}</IsTruncated>${truncated ? `<NextContinuationToken>${xmlEscape(page.at(-1))}</NextContinuationToken>` : ""}${contents}</ListBucketResult>`,
      );
    }

    // GetObject and HeadObject
    const key = segments.slice(1).join("/");
    const body = objects.get(key);
    if (body === undefined) {
      return send(404, s3Error("NoSuchKey", "The specified key does not exist.", `<Key>${xmlEscape(key)}</Key>`));
    }
    requests.push({ method: req.method, path: url.pathname, query: url.search, status: 200 });
    res.writeHead(200, {
      "Content-Type": "application/octet-stream",
      "Content-Length": body.length,
      ETag: `"${createHash("md5").update(body).digest("hex")}"`,
      "Last-Modified": lastModified.toUTCString(),
    });
    res.end(req.method === "HEAD" ? undefined : body);
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const url = `http://127.0.0.1:${server.address().port}`;

  return {
    url,
    requests,
    // True once the object was served in full to a GET.
    served: (key) => requests.some((r) => r.method === "GET" && r.status === 200 && r.path === `/${BUCKET}/${key}`),
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
