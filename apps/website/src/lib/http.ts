import "server-only";
import { NextResponse } from "next/server";
import { ZodError, type ZodType } from "zod";
import { env } from "./env";

export class HttpError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public extra?: Record<string, unknown>,
  ) {
    super(message);
  }
}

export const badRequest = (msg: string, extra?: Record<string, unknown>) => new HttpError(400, "bad_request", msg, extra);
export const unauthorized = (msg = "Authentication required.") => new HttpError(401, "unauthorized", msg);
export const forbidden = (msg = "You do not have access to this resource.") => new HttpError(403, "forbidden", msg);
export const notFound = (msg = "Not found.") => new HttpError(404, "not_found", msg);
export const conflict = (msg: string) => new HttpError(409, "conflict", msg);
export const tooMany = (retryAfterSec: number) =>
  new HttpError(429, "rate_limited", "Too many attempts. Please wait before trying again.", { retryAfter: retryAfterSec });

export function json(data: unknown, init?: ResponseInit) {
  return NextResponse.json(data, {
    ...init,
    headers: { "Cache-Control": "no-store", ...(init?.headers ?? {}) },
  });
}

/** Wraps a route handler with consistent error handling. */
export function handler<A extends unknown[]>(fn: (...args: A) => Promise<Response>) {
  return async (...args: A): Promise<Response> => {
    try {
      return await fn(...args);
    } catch (err) {
      if (err instanceof HttpError) {
        const headers: Record<string, string> = {};
        if (err.status === 429 && err.extra?.retryAfter) headers["Retry-After"] = String(err.extra.retryAfter);
        return json({ error: { code: err.code, message: err.message, ...(err.extra ?? {}) } }, { status: err.status, headers });
      }
      if (err instanceof ZodError) {
        return json(
          {
            error: {
              code: "validation_failed",
              message: "The request did not pass validation.",
              issues: err.issues.slice(0, 20).map((i) => ({ path: i.path.join("."), message: i.message })),
            },
          },
          { status: 422 },
        );
      }
      console.error("[api] unhandled error", err);
      return json({ error: { code: "internal", message: "An unexpected error occurred." } }, { status: 500 });
    }
  };
}

/** Reads and validates a JSON body with a hard byte limit (default 64 KiB). */
export async function readJson<T>(req: Request, schema: ZodType<T>, maxBytes = 64 * 1024): Promise<T> {
  const ct = req.headers.get("content-type") ?? "";
  if (!ct.toLowerCase().startsWith("application/json")) throw new HttpError(415, "unsupported_media_type", "Expected application/json.");
  const declared = Number(req.headers.get("content-length") ?? "0");
  if (declared > maxBytes) throw new HttpError(413, "payload_too_large", `Request body exceeds ${maxBytes} bytes.`);
  const reader = req.body?.getReader();
  if (!reader) throw badRequest("Missing request body.");
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new HttpError(413, "payload_too_large", `Request body exceeds ${maxBytes} bytes.`);
    }
    chunks.push(value);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw badRequest("Malformed JSON.");
  }
  return schema.parse(parsed);
}

export function clientIp(req: Request): string {
  // Client-supplied forwarding headers are only trusted when explicitly deployed behind
  // a reverse proxy that overwrites them (TRUST_PROXY=1). Otherwise every request shares
  // the "direct" bucket, which is conservative for rate limiting.
  if (process.env.TRUST_PROXY === "1") {
    const real = req.headers.get("x-real-ip");
    if (real) return real.trim();
    const fwd = req.headers.get("x-forwarded-for");
    if (fwd) return fwd.split(",")[0]!.trim();
  }
  return "direct";
}

/**
 * CSRF defence for cookie-authenticated, state-changing requests:
 * the Origin header (or Sec-Fetch-Site) must prove the request came from our own pages.
 * Session cookies are also SameSite=Lax.
 */
export function assertSameOrigin(req: Request): void {
  const origin = req.headers.get("origin");
  const allowed = new Set([env.appOrigin, new URL(req.url).origin]);
  if (origin) {
    if (!allowed.has(origin)) throw forbidden("Cross-site request rejected.");
    return;
  }
  const site = req.headers.get("sec-fetch-site");
  if (site && site !== "same-origin" && site !== "none") throw forbidden("Cross-site request rejected.");
  if (!site && env.isProduction) throw forbidden("Missing Origin header.");
}
