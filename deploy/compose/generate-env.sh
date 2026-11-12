#!/bin/sh
# Writes deploy/compose/.env from .env.example with freshly generated secrets.
# Refuses to overwrite an existing .env: replacing KMS_WRAPPING_KEY_B64 makes
# the existing database unreadable.
set -eu
cd "$(dirname "$0")"

if [ -e .env ]; then
  echo ".env already exists; not overwriting it (it holds the wrapping key)." >&2
  exit 1
fi
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }

umask 077
sed \
  -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(openssl rand -hex 24)|" \
  -e "s|^KMS_WRAPPING_KEY_B64=.*|KMS_WRAPPING_KEY_B64=$(openssl rand -base64 32)|" \
  -e "s|^KMS_AUDIT_HMAC_KEY_B64=.*|KMS_AUDIT_HMAC_KEY_B64=$(openssl rand -base64 32)|" \
  .env.example > .env
echo "Wrote $(pwd)/.env (mode 0600). Back up KMS_WRAPPING_KEY_B64 somewhere safe."
