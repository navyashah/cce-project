"""
FinCore — fictional fintech transaction database seed script.
Creates a realistic schema with deliberate PCI-7.1 misconfiguration:
card_data table has row-level security DISABLED by default (the vulnerability).
Running with FINCORE_SECURE=1 enables RLS (the fixed state).
"""
from __future__ import annotations
import os
import pathlib
from sqlalchemy import create_engine, text

FINCORE_DDL = """
-- ============================================================
-- FinCore Sample Fintech Database
-- ============================================================

CREATE SCHEMA IF NOT EXISTS fincore;

-- Customers
CREATE TABLE IF NOT EXISTS fincore.customers (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    email       TEXT NOT NULL UNIQUE,
    kyc_status  TEXT NOT NULL DEFAULT 'pending',
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Card data — the sensitive table PCI-7.1 protects
CREATE TABLE IF NOT EXISTS fincore.card_data (
    id              SERIAL PRIMARY KEY,
    customer_id     INT REFERENCES fincore.customers(id),
    card_token      TEXT NOT NULL,           -- tokenised PAN
    last_four       TEXT NOT NULL,
    card_brand      TEXT NOT NULL,
    expiry_month    INT NOT NULL,
    expiry_year     INT NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Transactions
CREATE TABLE IF NOT EXISTS fincore.transactions (
    id              SERIAL PRIMARY KEY,
    customer_id     INT REFERENCES fincore.customers(id),
    amount_cents    BIGINT NOT NULL,
    currency        TEXT NOT NULL DEFAULT 'USD',
    status          TEXT NOT NULL DEFAULT 'pending',
    merchant        TEXT NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Audit log — PCI-10.1 checks this exists and is populated
CREATE TABLE IF NOT EXISTS fincore.audit_log (
    id              SERIAL PRIMARY KEY,
    event_type      TEXT NOT NULL,
    table_name      TEXT NOT NULL,
    record_id       INT,
    performed_by    TEXT NOT NULL,
    performed_at    TIMESTAMPTZ DEFAULT NOW(),
    details         JSONB
);

-- User roles table (CC6.1 checks this for MFA enforcement)
CREATE TABLE IF NOT EXISTS fincore.user_roles (
    id          SERIAL PRIMARY KEY,
    username    TEXT NOT NULL UNIQUE,
    role        TEXT NOT NULL,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE
);
"""

SEED_DATA = """
-- Customers
INSERT INTO fincore.customers (name, email, kyc_status) VALUES
  ('Alice Merchant', 'alice@acme.com', 'verified'),
  ('Bob Payments', 'bob@finco.io', 'verified'),
  ('Carol Transfers', 'carol@payments.net', 'pending'),
  ('Dave Capital', 'dave@capital.co', 'verified')
ON CONFLICT DO NOTHING;

-- Card data (tokenised — no real PANs)
INSERT INTO fincore.card_data (customer_id, card_token, last_four, card_brand, expiry_month, expiry_year) VALUES
  (1, 'tok_visa_4242',  '4242', 'visa',       12, 2027),
  (2, 'tok_mc_5555',    '5555', 'mastercard', 06, 2026),
  (3, 'tok_amex_3714',  '3714', 'amex',       09, 2028),
  (4, 'tok_visa_1234',  '1234', 'visa',       03, 2027)
ON CONFLICT DO NOTHING;

-- Transactions
INSERT INTO fincore.transactions (customer_id, amount_cents, currency, status, merchant) VALUES
  (1, 9999,  'USD', 'completed', 'Stripe Inc'),
  (1, 4900,  'USD', 'completed', 'Shopify'),
  (2, 150000,'USD', 'completed', 'B2B Transfer'),
  (3, 2500,  'USD', 'pending',   'Square'),
  (4, 75000, 'USD', 'completed', 'Wire Transfer')
ON CONFLICT DO NOTHING;

-- Audit log entries
INSERT INTO fincore.audit_log (event_type, table_name, record_id, performed_by, details) VALUES
  ('SELECT', 'card_data', 1, 'api_service',    '{"reason": "payment processing"}'),
  ('SELECT', 'card_data', 2, 'api_service',    '{"reason": "payment processing"}'),
  ('UPDATE', 'transactions', 1, 'api_service', '{"status": "completed"}'),
  ('SELECT', 'card_data', 3, 'admin_user',     '{"reason": "support lookup"}')
ON CONFLICT DO NOTHING;

-- User roles (1 admin without MFA — triggers CC6.1 in drift mode)
INSERT INTO fincore.user_roles (username, role, mfa_enabled) VALUES
  ('api_service',  'service_account', TRUE),
  ('admin_user',   'admin',           FALSE),
  ('analyst_read', 'read_only',       TRUE)
ON CONFLICT DO NOTHING;
"""

def seed_fincore(database_url: str, secure_mode: bool = True):
    """
    Create and seed the FinCore database.
    Only runs on PostgreSQL — skips gracefully on SQLite (local dev).
    secure_mode=True  → RLS enabled on card_data (PCI-7.1 PASS)
    secure_mode=False → RLS disabled (PCI-7.1 FAIL — the vulnerability)
    """
    if database_url.startswith("sqlite"):
        print("FinCore: skipping seed on SQLite (PostgreSQL only)")
        return

    engine = create_engine(database_url)
    with engine.connect() as conn:
        # Run DDL statements one at a time (psycopg2 doesn't support multi-statement execute)
        for stmt in FINCORE_DDL.strip().split(";"):
            clean = "\n".join(l for l in stmt.splitlines() if not l.strip().startswith("--")).strip()
            if clean:
                conn.execute(text(clean))

        for stmt in SEED_DATA.strip().split(";"):
            clean = "\n".join(l for l in stmt.splitlines() if not l.strip().startswith("--")).strip()
            if clean:
                conn.execute(text(clean))

        if secure_mode:
            conn.execute(text("ALTER TABLE fincore.card_data ENABLE ROW LEVEL SECURITY"))
        else:
            conn.execute(text("ALTER TABLE fincore.card_data DISABLE ROW LEVEL SECURITY"))

        conn.commit()
    print(f"FinCore seeded. RLS on card_data: {'ENABLED' if secure_mode else 'DISABLED'}")

if __name__ == "__main__":
    from db.config import settings
    secure = os.getenv("FINCORE_SECURE", "1") == "1"
    seed_fincore(settings.database_url, secure_mode=secure)
