-- Instance-scoped scanning: richer findings and signature metadata.
ALTER TABLE "Detection" ADD COLUMN "family" TEXT;
ALTER TABLE "Detection" ADD COLUMN "signature" TEXT;
ALTER TABLE "Detection" ADD COLUMN "location" TEXT;

ALTER TABLE "DetectionRule" ADD COLUMN "scopes" TEXT[] DEFAULT ARRAY[]::TEXT[];
ALTER TABLE "DetectionRule" ADD COLUMN "weight" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "DetectionRule" ADD COLUMN "packages" TEXT[] DEFAULT ARRAY[]::TEXT[];
