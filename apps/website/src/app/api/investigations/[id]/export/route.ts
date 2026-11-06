import { handler, badRequest } from "@/lib/http";
import { requireUser } from "@/lib/auth/session";
import { buildSnapshot, getAuthorizedInvestigation } from "@/lib/investigations";
import { reportToCsv, reportToJson, reportToPdf } from "@/lib/report";
import { audit } from "@/lib/audit";

export const runtime = "nodejs";

export const GET = handler(async (req: Request, ctx: { params: Promise<{ id: string }> }) => {
  const { id } = await ctx.params;
  const user = await requireUser();
  await getAuthorizedInvestigation(id, user);
  const format = new URL(req.url).searchParams.get("format") ?? "json";
  const snap = await buildSnapshot(id);
  await audit({ actorType: user.role === "ADMIN" ? "ADMIN" : "USER", actorId: user.id, action: "investigation.export", targetType: "Investigation", targetId: id, details: { format } });
  const base = `screensharing-${snap.reference}`;
  const disp = (ext: string) => ({ "Content-Disposition": `attachment; filename="${base}.${ext}"`, "Cache-Control": "no-store" });
  switch (format) {
    case "json":
      return new Response(reportToJson(snap), { headers: { "Content-Type": "application/json; charset=utf-8", ...disp("json") } });
    case "csv":
      return new Response(reportToCsv(snap), { headers: { "Content-Type": "text/csv; charset=utf-8", ...disp("csv") } });
    case "pdf":
      return new Response(Buffer.from(await reportToPdf(snap)), { headers: { "Content-Type": "application/pdf", ...disp("pdf") } });
    default:
      throw badRequest("Unsupported format. Use json, csv or pdf.");
  }
});
