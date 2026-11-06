// Starts a local PostgreSQL server for development using the official
// PostgreSQL binaries shipped by the `embedded-postgres` npm package.
// Production deployments must use a managed/real PostgreSQL via DATABASE_URL.
import EmbeddedPostgres from "embedded-postgres";
import { fileURLToPath } from "node:url";
import path from "node:path";
import fs from "node:fs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const dataDir = path.join(root, "database", ".pgdata");
const port = Number(process.env.DEV_PG_PORT ?? 5433);
const password = process.env.DEV_PG_PASSWORD ?? "ssme_dev_pw";

const pg = new EmbeddedPostgres({
  databaseDir: dataDir,
  user: "ssme",
  password,
  port,
  persistent: true,
  // UTF-8 regardless of the Windows code page: mod names and paths contain non-Latin characters.
  initdbFlags: ["--encoding=UTF8", "--locale=C"],
  onLog: () => {},
});

const fresh = !fs.existsSync(path.join(dataDir, "PG_VERSION"));
if (fresh) {
  console.log("[dev-db] initialising cluster at", dataDir);
  await pg.initialise();
}
await pg.start();
if (fresh) {
  await pg.createDatabase("screensharing");
  await pg.createDatabase("screensharing_test");
}
console.log(`[dev-db] PostgreSQL listening on 127.0.0.1:${port} (databases: screensharing, screensharing_test)`);

const shutdown = async () => {
  console.log("[dev-db] stopping");
  await pg.stop();
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
setInterval(() => {}, 1 << 30);
