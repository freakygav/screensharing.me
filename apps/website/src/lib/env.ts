import "server-only";

function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required environment variable ${name}`);
  return v;
}

function int(name: string, fallback: number): number {
  const v = process.env[name];
  const n = v ? Number.parseInt(v, 10) : fallback;
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

export const env = {
  get appSecret(): string {
    const s = required("APP_SECRET");
    if (s.length < 32) throw new Error("APP_SECRET must be at least 32 characters");
    return s;
  },
  get appOrigin(): string {
    return (process.env.APP_ORIGIN ?? "http://localhost:3000").replace(/\/$/, "");
  },
  get isProduction(): boolean {
    return process.env.NODE_ENV === "production";
  },
  pinTtlMinutes: int("PIN_TTL_MINUTES", 15),
  desktopTokenTtlMinutes: int("DESKTOP_TOKEN_TTL_MINUTES", 120),
  webSessionDays: 7,
  adminSessionHours: 8,
  desktopStaffSessionHours: 8,
};
