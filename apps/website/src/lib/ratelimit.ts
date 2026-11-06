import "server-only";
import { db } from "./db";
import { tooMany } from "./http";

/**
 * Fixed-window rate limiter stored in PostgreSQL so it holds across
 * multiple server instances. One atomic upsert per check.
 */
export async function hit(key: string, limit: number, windowSec: number): Promise<{ count: number; allowed: boolean }> {
  const rows = await db.$queryRaw<{ count: number }[]>`
    INSERT INTO "RateLimitBucket" ("key", "count", "windowStart")
    VALUES (${key}, 1, now())
    ON CONFLICT ("key") DO UPDATE SET
      "count" = CASE WHEN "RateLimitBucket"."windowStart" < now() - make_interval(secs => ${windowSec})
                     THEN 1 ELSE "RateLimitBucket"."count" + 1 END,
      "windowStart" = CASE WHEN "RateLimitBucket"."windowStart" < now() - make_interval(secs => ${windowSec})
                     THEN now() ELSE "RateLimitBucket"."windowStart" END
    RETURNING "count"`;
  const count = Number(rows[0]?.count ?? 0);
  return { count, allowed: count <= limit };
}

export async function enforce(key: string, limit: number, windowSec: number): Promise<void> {
  const r = await hit(key, limit, windowSec);
  if (!r.allowed) throw tooMany(windowSec);
}

/** Read the current count without incrementing. */
export async function peek(key: string, windowSec: number): Promise<number> {
  const row = await db.rateLimitBucket.findUnique({ where: { key } });
  if (!row) return 0;
  if (row.windowStart.getTime() < Date.now() - windowSec * 1000) return 0;
  return row.count;
}

export async function reset(key: string): Promise<void> {
  await db.rateLimitBucket.deleteMany({ where: { key } });
}
