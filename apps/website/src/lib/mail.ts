import "server-only";
import { db } from "./db";

/**
 * Outbound mail. Messages are always recorded in MailOutbox. When SMTP_URL is
 * configured they are also delivered via SMTP (nodemailer, loaded lazily so the
 * dependency is optional for local development).
 */
export async function sendMail(to: string, subject: string, body: string): Promise<void> {
  const row = await db.mailOutbox.create({ data: { to, subject, body } });
  const smtp = process.env.SMTP_URL;
  if (!smtp) {
    if (process.env.NODE_ENV !== "production") console.info(`[mail] (outbox only) to=${to} subject="${subject}"\n${body}`);
    return;
  }
  try {
    const mod = (await import(/* webpackIgnore: true */ "nodemailer" as string)) as {
      createTransport: (url: string) => { sendMail: (m: object) => Promise<unknown> };
    };
    await mod.createTransport(smtp).sendMail({
      from: process.env.MAIL_FROM ?? "screensharing.me <no-reply@screensharing.me>",
      to,
      subject,
      text: body,
    });
    await db.mailOutbox.update({ where: { id: row.id }, data: { sentAt: new Date() } });
  } catch (err) {
    await db.mailOutbox.update({ where: { id: row.id }, data: { error: String(err).slice(0, 500) } });
  }
}
