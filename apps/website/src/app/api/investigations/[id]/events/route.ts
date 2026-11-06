import { db } from "@/lib/db";
import { bus } from "@/lib/events";
import { handler } from "@/lib/http";
import { requireUser } from "@/lib/auth/session";
import { getAuthorizedInvestigation } from "@/lib/investigations";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
// Serverless hosts (e.g. Vercel) cap function duration. Each stream ends itself before the cap and
// the browser's EventSource reconnects with Last-Event-ID, so no update is lost.
export const maxDuration = 300;
const STREAM_LIFETIME_MS = Number(process.env.SSE_MAX_SECONDS ?? 240) * 1000;

/**
 * Server-Sent Events stream of investigation updates.
 * - Resumable: honours Last-Event-ID (or ?after=) so reconnecting clients miss nothing.
 * - Wakes immediately on in-process events and polls the durable event table every 2s
 *   so updates from other server instances are also delivered.
 */
export const GET = handler(async (req: Request, ctx: { params: Promise<{ id: string }> }) => {
  const { id } = await ctx.params;
  const user = await requireUser();
  await getAuthorizedInvestigation(id, user);

  const url = new URL(req.url);
  const resumeFrom = req.headers.get("last-event-id") ?? url.searchParams.get("after") ?? "0";
  let lastId = /^\d+$/.test(resumeFrom) ? BigInt(resumeFrom) : 0n;
  const encoder = new TextEncoder();
  let closed = false;

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      let wake: (() => void) | null = null;
      const onBus = () => wake?.();
      bus.on(`inv:${id}`, onBus);
      const send = (s: string) => {
        if (!closed) controller.enqueue(encoder.encode(s));
      };
      const cleanup = () => {
        if (closed) return;
        closed = true;
        bus.off(`inv:${id}`, onBus);
        try { controller.close(); } catch { /* already closed */ }
      };
      req.signal.addEventListener("abort", cleanup);
      send("retry: 3000\n\n");

      (async () => {
        let lastPing = Date.now();
        const startedAt = Date.now();
        while (!closed) {
          if (Date.now() - startedAt > STREAM_LIFETIME_MS) { cleanup(); break; }
          const events = await db.investigationEvent.findMany({
            where: { investigationId: id, id: { gt: lastId } },
            orderBy: { id: "asc" },
            take: 200,
          });
          for (const e of events) {
            lastId = e.id;
            send(`id: ${e.id}\nevent: update\ndata: ${JSON.stringify({ type: e.type, payload: e.payload, at: e.createdAt })}\n\n`);
          }
          if (Date.now() - lastPing > 15_000) {
            send(`: ping\n\n`);
            lastPing = Date.now();
          }
          await new Promise<void>((resolve) => {
            const t = setTimeout(resolve, 2000);
            wake = () => { clearTimeout(t); resolve(); };
          });
          wake = null;
        }
      })().catch(cleanup);
    },
    cancel() {
      closed = true;
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream; charset=utf-8",
      "Cache-Control": "no-store, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
});
