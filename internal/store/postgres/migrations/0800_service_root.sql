-- One deployment root secret, wrapped like any other key material. Keys that
-- used to be HKDF-derived straight from the wrapping key (audit chain MAC,
-- value fingerprints, sealed SSO client secrets, the audit-stream token, SSO
-- state cookies) are now derived from this secret instead, so rotating the
-- wrapping key re-wraps one row rather than changing every derived key.
CREATE TABLE IF NOT EXISTS service_keys (
  purpose TEXT PRIMARY KEY,
  key_wrapped_b64 TEXT NOT NULL,
  key_nonce_b64 TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
