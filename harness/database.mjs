// A throwaway database server in a Docker container, for indexers that persist
// to Postgres. Each replay gets its own database on it.

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function docker(args, options = {}) {
  const { stdout } = await run("docker", args, { encoding: "utf8", maxBuffer: 16 * 1024 * 1024, ...options });
  return stdout.trim();
}

// `image` and `args` come from the adapter, which knows what its indexer needs.
export async function startDatabase({ image, args = [] }) {
  const container = `xdr-corpus-replay-${process.pid}`;
  await docker([
    "run", "--detach", "--rm", "--name", container,
    "--env", "POSTGRES_HOST_AUTH_METHOD=trust",
    "--publish", "127.0.0.1::5432",
    image, ...args,
  ]);

  const stop = async () => {
    await docker(["rm", "--force", "--volumes", container]).catch(() => {});
  };

  try {
    const port = (await docker(["port", container, "5432/tcp"])).split("\n")[0].split(":").pop();

    // Run one statement, or several separated by semicolons, and return what
    // psql prints: unaligned rows, columns separated by tabs.
    const sql = (database, text) =>
      docker(["exec", container, "psql", "--username", "postgres", "--host", "127.0.0.1",
        "--dbname", database, "--set", "ON_ERROR_STOP=1", "--no-psqlrc", "--quiet",
        "--tuples-only", "--no-align", "--field-separator", "\t", "--command", text]);

    // The image starts Postgres once on a socket to initialise it and then
    // restarts it on TCP, so only a TCP connection proves it is ready.
    const deadline = Date.now() + 120_000;
    for (;;) {
      try {
        await sql("postgres", "SELECT 1");
        break;
      } catch (error) {
        if (Date.now() > deadline) throw new Error(`database did not become ready: ${error.message}`);
        await sleep(500);
      }
    }

    return {
      sql,
      url: (database) => `postgres://postgres@127.0.0.1:${port}/${database}?sslmode=disable`,
      stop,
    };
  } catch (error) {
    await stop();
    throw error;
  }
}
