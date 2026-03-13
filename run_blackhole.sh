#!/usr/bin/env bash
set -euo pipefail
export BLACKHOLE_PACK="${BLACKHOLE_PACK:-/mnt/data/blackhole_mock_server/examples/starter-pack.yaml}"
uvicorn blackhole.app.main:app --host 0.0.0.0 --port "${PORT:-8010}"
