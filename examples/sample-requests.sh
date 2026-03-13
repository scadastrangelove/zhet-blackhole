#!/usr/bin/env bash
set -euo pipefail

base="${1:-http://127.0.0.1:8010}"

curl -i "$base/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
echo
curl -i "$base/redirect?next=https://evil.example" --max-redirs 0 || true
echo
curl -i -H 'Origin: https://attacker.example' "$base/api/account"
echo
curl -i "$base/.env"
echo
curl -i "$base/download?file=../../etc/passwd"
echo
curl -i -X POST "$base/graphql" -H 'content-type: application/json' -d '{"query":"{ __schema { types { name } } }"}'
