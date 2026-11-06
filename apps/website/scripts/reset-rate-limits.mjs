// Development helper: clears all rate-limit buckets (e.g. after running the test suites repeatedly).
import { PrismaClient } from "@prisma/client";
const db = new PrismaClient();
const r = await db.rateLimitBucket.deleteMany({});
console.log(`cleared ${r.count} rate-limit buckets`);
await db.$disconnect();
