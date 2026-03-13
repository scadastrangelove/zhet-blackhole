from __future__ import annotations

import json
import re
from typing import Any, Optional

from starlette.requests import Request

from .models import FieldMatcher, JsonMatcher, ReplayProfile


def _normalize_matcher(raw: FieldMatcher | str) -> FieldMatcher:
    if isinstance(raw, FieldMatcher):
        return raw
    if raw == "any":
        return FieldMatcher(any_value=True)
    return FieldMatcher(exact=str(raw))


def _match_value(value: Optional[str], matcher: FieldMatcher) -> bool:
    if matcher.absent:
        return value is None
    if matcher.present:
        return value is not None
    if value is None:
        return False
    if matcher.any_value:
        return True
    if matcher.exact is not None and value != matcher.exact:
        return False
    if matcher.contains is not None and matcher.contains not in value:
        return False
    if matcher.regex is not None and not re.search(matcher.regex, value):
        return False
    if matcher.one_of is not None and value not in matcher.one_of:
        return False
    return True


def _get_json_path(data: Any, path: str) -> Any:
    if not path.startswith("$"):
        raise ValueError("JSON path must start with $")
    cur = data
    tokens = [token for token in path.lstrip("$").split(".") if token]
    for token in tokens:
        if isinstance(cur, dict) and token in cur:
            cur = cur[token]
        else:
            return None
    return cur


def _match_json(data: Any, matcher: JsonMatcher) -> bool:
    value = _get_json_path(data, matcher.path)
    if matcher.present is True:
        return value is not None
    if value is None:
        return False
    as_text = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
    if matcher.exact is not None and value != matcher.exact:
        return False
    if matcher.contains is not None and matcher.contains not in as_text:
        return False
    if matcher.regex is not None and not re.search(matcher.regex, as_text):
        return False
    return True


def _match_path(request_path: str, profile: ReplayProfile) -> bool:
    matcher = profile.matcher
    if matcher.path is not None and request_path != matcher.path:
        return False
    if matcher.path_regex is not None and not re.search(matcher.path_regex, request_path):
        return False
    if matcher.path_template is not None:
        pattern = re.sub(r"\{[^/]+\}", r"[^/]+", matcher.path_template)
        pattern = f"^{pattern}$"
        if not re.match(pattern, request_path):
            return False
    return True


async def match_request(request: Request, profile: ReplayProfile) -> bool:
    matcher = profile.matcher
    if not profile.enabled:
        return False
    if matcher.method.upper() != "ANY" and request.method.upper() != matcher.method.upper():
        return False
    if not _match_path(request.url.path, profile):
        return False

    query_params = request.query_params
    for key, raw in matcher.query.items():
        if not _match_value(query_params.get(key), _normalize_matcher(raw)):
            return False

    headers = {k.lower(): v for k, v in request.headers.items()}
    for key, raw in matcher.headers.items():
        if not _match_value(headers.get(key.lower()), _normalize_matcher(raw)):
            return False

    for key, raw in matcher.cookies.items():
        if not _match_value(request.cookies.get(key), _normalize_matcher(raw)):
            return False

    body = await request.body()
    body_text = body.decode("utf-8", errors="replace")
    if matcher.body_contains is not None and matcher.body_contains not in body_text:
        return False
    if matcher.body_regex is not None and not re.search(matcher.body_regex, body_text, flags=re.DOTALL):
        return False

    if matcher.json_fields:
        try:
            json_body = json.loads(body_text) if body_text else None
        except json.JSONDecodeError:
            return False
        for json_matcher in matcher.json_fields:
            if not _match_json(json_body, json_matcher):
                return False

    return True
