from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional

from jinja2 import Environment
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .models import ReplayProfile


def _safe_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)


def build_environment() -> Environment:
    env = Environment(autoescape=False)
    env.filters["tojson_pretty"] = _safe_json
    return env


def _context_from_request(
    request: Request,
    body_text: str,
    json_body: Optional[Dict[str, Any]],
    state_snapshot: Dict[str, Any],
    memory_snapshot: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "request": {
            "method": request.method,
            "path": request.url.path,
            "query": dict(request.query_params),
            "headers": dict(request.headers),
            "cookies": request.cookies,
            "body": body_text,
            "json": json_body,
        },
        "query": dict(request.query_params),
        "headers": dict(request.headers),
        "cookies": request.cookies,
        "body_text": body_text,
        "json_body": json_body,
        "state": state_snapshot,
        "memory": memory_snapshot,
    }


async def render_profile_response(
    request: Request,
    profile: ReplayProfile,
    env: Environment,
    state_snapshot: Dict[str, Any],
    memory_snapshot: Dict[str, Any],
) -> Response:
    body_bytes = await request.body()
    body_text = body_bytes.decode("utf-8", errors="replace")
    try:
        json_body = json.loads(body_text) if body_text else None
    except json.JSONDecodeError:
        json_body = None

    ctx = _context_from_request(request, body_text, json_body, state_snapshot, memory_snapshot)

    if profile.response.delay_ms:
        time.sleep(profile.response.delay_ms / 1000.0)

    rendered_headers = {key: env.from_string(value).render(**ctx) for key, value in profile.response.headers.items()}

    if profile.response.body_json is not None:
        rendered_json = json.loads(env.from_string(_safe_json(profile.response.body_json)).render(**ctx))
        return JSONResponse(rendered_json, status_code=profile.response.status, headers=rendered_headers)

    rendered_body = env.from_string(profile.response.body_template).render(**ctx)
    media_type = profile.response.media_type or rendered_headers.get("Content-Type")
    return Response(
        content=rendered_body,
        status_code=profile.response.status,
        headers=rendered_headers,
        media_type=media_type,
    )
