import "server-only";
import { PrismaClient } from "@prisma/client";

const globalForPrisma = globalThis as unknown as { __ssmePrisma?: PrismaClient };

export const db: PrismaClient =
  globalForPrisma.__ssmePrisma ??
  new PrismaClient({ log: process.env.PRISMA_LOG ? ["query", "warn", "error"] : ["warn", "error"] });

if (process.env.NODE_ENV !== "production") globalForPrisma.__ssmePrisma = db;
