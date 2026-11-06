import "server-only";
import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, randomInt, timingSafeEqual } from "node:crypto";
import { env } from "./env";

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

export function sha256Hex(input: string | Buffer): string {
  return createHash("sha256").update(input).digest("hex");
}

export function hmacHex(purpose: string, value: string): string {
  return createHmac("sha256", env.appSecret).update(`${purpose}:${value}`).digest("hex");
}

export function safeEqualHex(a: string, b: string): boolean {
  const ba = Buffer.from(a, "hex");
  const bb = Buffer.from(b, "hex");
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

function sealKey(): Buffer {
  return createHash("sha256").update(`ssme-seal-v1:${env.appSecret}`).digest();
}

/** AES-256-GCM encryption for short secrets that must be re-displayed (pending PINs). */
export function seal(plaintext: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", sealKey(), iv);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return [iv, cipher.getAuthTag(), ct].map((b) => b.toString("base64url")).join(".");
}

export function unseal(sealed: string): string | null {
  try {
    const [iv, tag, ct] = sealed.split(".").map((p) => Buffer.from(p, "base64url"));
    const decipher = createDecipheriv("aes-256-gcm", sealKey(), iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
  } catch {
    return null;
  }
}

/** Six-digit PIN from a CSPRNG, formatted for display as "483-921". */
export function generatePinDigits(): string {
  return randomInt(0, 1_000_000).toString().padStart(6, "0");
}

export function formatPin(digits: string): string {
  return `${digits.slice(0, 3)}-${digits.slice(3)}`;
}

export function normalizePin(input: string): string | null {
  const digits = input.replace(/[\s-]/g, "");
  return /^\d{6}$/.test(digits) ? digits : null;
}

const REF_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"; // no 0/O/1/I
export function generateReference(): string {
  const pick = () => Array.from({ length: 4 }, () => REF_ALPHABET[randomInt(0, REF_ALPHABET.length)]).join("");
  return `INV-${pick()}-${pick()}`;
}
