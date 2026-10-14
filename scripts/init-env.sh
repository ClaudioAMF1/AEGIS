#!/usr/bin/env sh
# Creates .env from .env.example with freshly generated secrets.
# Usage: ./scripts/init-env.sh   (refuses to overwrite an existing .env)
set -eu
cd "$(dirname "$0")/.."

if [ -e .env ]; then
  echo ".env already exists; remove it first if you really want new secrets" >&2
  echo "(changing AEGIS_SECRET_KEY invalidates sessions, agent tokens and MFA)" >&2
  exit 1
fi

random() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 "$1" | tr -d '\n/+=' 
  else
    python3 -c "import secrets,sys; print(secrets.token_urlsafe(int(sys.argv[1])), end='')" "$1"
  fi
}

secret_key=$(random 48)
db_password=$(random 24)

umask 077
sed -e "s|^AEGIS_SECRET_KEY=.*|AEGIS_SECRET_KEY=${secret_key}|" \
    -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${db_password}|" \
    .env.example > .env

echo "created .env with a new AEGIS_SECRET_KEY and POSTGRES_PASSWORD (mode 600)"
echo "next: docker compose up -d --build"
