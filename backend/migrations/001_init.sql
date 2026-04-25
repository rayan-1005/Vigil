-- migrations/001_init.sql
-- Run once: psql $DATABASE_URL -f migrations/001_init.sql

BEGIN;

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── institutions ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS institutions (
  id            UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  name          VARCHAR(200)  NOT NULL,
  email         VARCHAR(200)  NOT NULL UNIQUE,
  password_hash VARCHAR(255)  NOT NULL,
  role          VARCHAR(20)   NOT NULL DEFAULT 'institution'
                              CHECK (role IN ('institution', 'admin')),
  -- SECURITY: api_key stores HMAC-SHA256 hash, never plaintext
  api_key       VARCHAR(64)   UNIQUE,
  is_active     BOOLEAN       NOT NULL DEFAULT TRUE,
  created_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_institutions_email ON institutions(email);

-- ── scan_requests ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_requests (
  id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  institution_id UUID         REFERENCES institutions(id) ON DELETE SET NULL,
  raw_message    TEXT         NOT NULL,
  source         VARCHAR(20)  NOT NULL DEFAULT 'sms'
                              CHECK (source IN ('sms','whatsapp','upi_app','other')),
  ip_address     INET,
  user_agent     TEXT,
  status         VARCHAR(20)  NOT NULL DEFAULT 'pending'
                              CHECK (status IN ('pending','processing','done','error')),
  created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_scan_req_institution ON scan_requests(institution_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_req_status      ON scan_requests(status);

-- ── scan_results ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_results (
  id                 UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_request_id    UUID         REFERENCES scan_requests(id) ON DELETE CASCADE UNIQUE,
  detected_language  VARCHAR(10),
  translated_message TEXT,
  risk_score         SMALLINT     CHECK (risk_score BETWEEN 0 AND 100),
  risk_level         VARCHAR(10)  NOT NULL CHECK (risk_level IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  classification     VARCHAR(20)  NOT NULL CHECK (classification IN ('FRAUDULENT','SUSPICIOUS','LEGITIMATE')),
  confidence         NUMERIC(5,4),
  explanation        TEXT,
  flags              TEXT[]       DEFAULT '{}',
  entities           JSONB        DEFAULT '{}',
  pattern_matches    JSONB        DEFAULT '[]',
  hf_latency_ms      INTEGER,
  created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_scan_res_risk     ON scan_results(risk_level, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_res_lang     ON scan_results(detected_language);
CREATE INDEX IF NOT EXISTS idx_scan_res_flags    ON scan_results USING GIN(flags);
CREATE INDEX IF NOT EXISTS idx_scan_res_entities ON scan_results USING GIN(entities);

-- ── alerts ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
  id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_result_id   UUID         REFERENCES scan_results(id) ON DELETE CASCADE,
  institution_id   UUID         REFERENCES institutions(id) ON DELETE CASCADE,
  risk_score       SMALLINT,
  risk_level       VARCHAR(10),
  flags            TEXT[]       DEFAULT '{}',
  delivered_at     TIMESTAMPTZ,
  acknowledged_at  TIMESTAMPTZ,
  created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_alerts_institution    ON alerts(institution_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_unacknowledged ON alerts(institution_id) WHERE acknowledged_at IS NULL;

-- ── scam_patterns ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scam_patterns (
  id            UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  name          VARCHAR(100)  NOT NULL UNIQUE,
  description   TEXT,
  pattern_type  VARCHAR(20)   NOT NULL CHECK (pattern_type IN ('regex','keyword','domain','upi_id')),
  pattern_value TEXT          NOT NULL,
  severity      VARCHAR(10)   NOT NULL DEFAULT 'MEDIUM'
                              CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  is_active     BOOLEAN       NOT NULL DEFAULT TRUE,
  hit_count     INTEGER       NOT NULL DEFAULT 0,
  created_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_scam_patterns_active ON scam_patterns(is_active, pattern_type);

-- ── updated_at trigger ────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER trg_institutions_updated_at
  BEFORE UPDATE ON institutions
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE OR REPLACE TRIGGER trg_scam_patterns_updated_at
  BEFORE UPDATE ON scam_patterns
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

COMMIT;
