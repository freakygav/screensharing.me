"use client";

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string, public issues?: { path: string; message: string }[]) {
    super(message);
  }
}

export async function api<T = unknown>(path: string, opts: { method?: string; body?: unknown } = {}): Promise<T> {
  const res = await fetch(path, {
    method: opts.method ?? (opts.body ? "POST" : "GET"),
    headers: opts.body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    credentials: "same-origin",
    cache: "no-store",
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const e = (data as { error?: { code?: string; message?: string; issues?: { path: string; message: string }[] } }).error;
    const msg = e?.issues?.length ? e.issues.map((i) => i.message).join(" ") : e?.message;
    throw new ApiError(res.status, e?.code ?? "error", msg ?? `Request failed (${res.status}).`, e?.issues);
  }
  return data as T;
}
