from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import yaml


SUPPORTED_SECTIONS = {
    "xss",
    "cors",
    "redirect",
    "graphql",
    "exposure",
    "file-access",
    "injection",
    "ssrf",
    "discovery",
    "misconfig",
    "secrets",
    "access-control",
    "auth",
    "csrf",
    "xxe",
    "crypto",
    "file-upload",
    "intro",
}


def sanitize_path(candidate: str) -> str:
    cleaned = candidate.strip()
    cleaned = cleaned.replace(r"\b", "")
    cleaned = cleaned.replace("(?:", "")
    cleaned = cleaned.replace("(", "")
    cleaned = cleaned.replace(")", "")
    cleaned = cleaned.replace("^", "")
    cleaned = cleaned.replace("$", "")
    cleaned = cleaned.replace(".*", "")
    cleaned = cleaned.replace("|", "")
    cleaned = cleaned.replace("?", "")
    cleaned = cleaned.replace("\\", "")
    cleaned = cleaned.replace("#", "")
    cleaned = re.sub(r"/+", "/", cleaned)
    if not cleaned.startswith("/"):
        cleaned = f"/{cleaned.lstrip('/')}"
    cleaned = cleaned.strip()
    if not cleaned or cleaned == "/":
        return "/"
    return cleaned


PATH_HINTS = {
    "auth": "/oauth/authorize",
    "access-control": "/admin",
    "csrf": "/account/change-email",
    "xxe": "/api/xml",
    "crypto": "/crypto/verify",
    "file-upload": "/upload",
    "intro": "/healthz",
}


PARAM_HINTS = {
    "xss": "q",
    "redirect": "next",
    "injection": "id",
    "ssrf": "url",
    "auth": "redirect_uri",
    "csrf": "email",
    "crypto": "token",
    "file-upload": "filename",
}


def choose_path(endpoint_patterns: list[str] | None, fallback: str) -> str:
    if endpoint_patterns:
        for pattern in endpoint_patterns:
            if not pattern:
                continue
            cleaned = sanitize_path(pattern)
            if cleaned and cleaned != "/":
                return cleaned
    return sanitize_path(fallback)


def choose_param(seed_params: list[str] | None, fallback: str) -> str:
    if not seed_params:
        return fallback
    for item in seed_params:
        if re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", item):
            return item
    return fallback


def profile_for_record(rec: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if rec.get("public_status") != "public":
        return None
    section = rec.get("north_star_section")
    if section == "oauth":
        section = "auth"
    if section not in SUPPORTED_SECTIONS:
        return None
    if rec.get("emulation_grade") not in {"replayable", "stateful"}:
        return None

    # normalized section may differ from source record if aliases were applied above
    case_id = rec["case_id"]
    title = rec["title"]
    vuln_class = rec["vuln_class_norm"]
    source_name = rec.get("source_name")
    source_url = rec.get("source_url")
    endpoint_patterns = rec.get("endpoint_pattern") or []
    seed_params = rec.get("seed_params") or []
    raw_path = choose_path(endpoint_patterns, PATH_HINTS.get(section, f"/{section}/{case_id}"))
    path = sanitize_path(f"/cases/{case_id}{raw_path}")
    param = choose_param(seed_params, PARAM_HINTS.get(section, "q"))

    base = {
        "id": f"compiled-{case_id}",
        "case_id": case_id,
        "title": title,
        "source_name": source_name,
        "source_url": source_url,
        "tags": [section, rec.get("app_family", "public-corpus")],
        "notes": [
            "Compiled heuristically from normalized public corpus.",
            f"Expected evidence: {rec.get('expected_evidence', '')}",
            f"Endpoint pattern status: {rec.get('endpoint_pattern_status', 'unknown')}",
        ],
        "truth": {
            "vuln_class": vuln_class,
            "positive_evidence": [rec.get("expected_evidence", "expected evidence")],
            "guardrails": ["Do not over-claim exploitability beyond replayed behavior."],
            "manual_followup": ["Confirm the issue against a realistic application when needed."],
            "confidence_cap": "medium",
            "emulation_grade": rec.get("emulation_grade", "replayable"),
            "automation_grade": rec.get("automation_grade", "signature"),
            "north_star_section": section,
            "delayed_effect": rec.get("statefulness") == "stateful",
            "second_order": rec.get("statefulness") == "stateful",
            "second_order_sink": rec.get("second_order_sink"),
            "requires_repeat": rec.get("statefulness") == "stateful",
        },
    }

    if section == "xss":
        return {
            **base,
            "matcher": {"method": "GET", "path": path, "query": {param: "any"}},
            "response": {
                "status": 200,
                "headers": {"Content-Type": "text/html; charset=utf-8"},
                "body_template": f"<html><body><h1>{title}</h1><div>Search: {{{{ query.{param} }}}}</div></body></html>",
            },
        }
    if section == "cors":
        return {
            **base,
            "matcher": {"method": "GET", "path": path, "headers": {"origin": "any"}},
            "response": {
                "status": 200,
                "headers": {
                    "Content-Type": "application/json",
                    "Access-Control-Allow-Origin": "{{ headers.Origin or headers.origin or '*' }}",
                    "Access-Control-Allow-Credentials": "true",
                },
                "body_template": '{"ok": true, "message": "cross-origin data exposed"}',
            },
        }
    if section == "redirect":
        return {
            **base,
            "matcher": {"method": "GET", "path": path, "query": {param: "any"}},
            "response": {
                "status": 302,
                "headers": {"Location": "{{ query.%s }}" % param},
                "body_template": "redirecting",
            },
        }
    if section in {"exposure", "file-access", "secrets", "discovery", "misconfig", "intro", "access-control"}:
        body = (
            f"# {title}\n"
            f"# case_id: {case_id}\n"
            f"# expected: {rec.get('expected_evidence', '')}\n"
            "api_key=EXAMPLE-LEAK-123456\n"
            "password=summer2026\n"
        )
        if section == "access-control":
            body = (
                f"<html><body><h1>Admin panel</h1><p>{title}</p>"
                "<div>role=admin</div><div>users_total=42</div></body></html>"
            )
        return {
            **base,
            "matcher": {"method": "GET", "path": path},
            "response": {
                "status": 200,
                "headers": {"Content-Type": "text/html; charset=utf-8" if section == "access-control" else "text/plain; charset=utf-8"},
                "body_template": body,
            },
        }
    if section == "graphql":
        return {
            **base,
            "matcher": {"method": "POST", "path": path if path != "/graphql/" else "/graphql", "body_contains": "__schema"},
            "response": {
                "status": 200,
                "headers": {"Content-Type": "application/json"},
                "body_template": '{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"Query"},{"name":"User"}]}}}',
            },
        }

    if section == "auth":
        query = {"client_id": "any", "redirect_uri": "any"}
        return {
            **base,
            "matcher": {"method": "GET", "path": path, "query": query},
            "response": {
                "status": 302,
                "headers": {"Location": "{{ query.redirect_uri }}?code=bhcode-demo&state=xyz"},
                "body_template": "authorizing",
            },
        }
    if section == "injection":
        return {
            **base,
            "matcher": {"method": "GET", "path": path, "query": {param: "any"}},
            "response": {
                "status": 500,
                "headers": {"Content-Type": "text/html; charset=utf-8"},
                "body_template": f"<html><body>SQLSTATE[42000]: Syntax error or access violation near '{{{{ query.{param} }}}}'</body></html>",
            },
        }
    if section == "ssrf":
        return {
            **base,
            "matcher": {"method": "GET", "path": path, "query": {param: "any"}},
            "response": {
                "status": 200,
                "headers": {"Content-Type": "application/json"},
                "body_template": f'{{"fetched_url": "{{{{ query.{param} }}}}", "simulated_fetch": true, "body": "localhost metadata"}}',
            },
        }
    if section == "csrf":
        return {
            **base,
            "matcher": {"method": "GET", "path": path, "query": {param: "any"}},
            "response": {
                "status": 200,
                "headers": {"Content-Type": "text/html; charset=utf-8"},
                "body_template": f"<html><body><h1>Change applied</h1><p>{param}={{{{ query.{param} }}}}</p><p>csrf_token=absent</p></body></html>",
            },
        }
    if section == "xxe":
        return {
            **base,
            "matcher": {"method": "POST", "path": path, "body_contains": "<!DOCTYPE"},
            "response": {
                "status": 200,
                "headers": {"Content-Type": "application/xml; charset=utf-8"},
                "body_template": "<response><status>ok</status><data>root:x:0:0:root:/root:/bin/bash</data></response>",
            },
        }
    if section == "crypto":
        return {
            **base,
            "matcher": {"method": "GET", "path": path, "query": {param: "any"}},
            "response": {
                "status": 200,
                "headers": {"Content-Type": "application/json"},
                "body_template": f'{{"token":"{{{{ query.{param} }}}}","accepted":true,"algorithm":"none"}}',
            },
        }
    if section == "file-upload":
        return {
            **base,
            "matcher": {"method": "POST", "path": path, "body_contains": "filename="},
            "response": {
                "status": 201,
                "headers": {"Content-Type": "application/json"},
                "body_template": '{"uploaded": true, "location": "/uploads/shell.php", "executed": true}',
            },
        }
    return None


def iter_records(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open() as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def compile_pack(input_path: Path, output_path: Path, name: str) -> Dict[str, Any]:
    profiles: List[Dict[str, Any]] = []
    unsupported: List[str] = []
    for rec in iter_records(input_path):
        profile = profile_for_record(rec)
        if profile is None:
            unsupported.append(rec.get("case_id", "unknown"))
            continue
        profiles.append(profile)

    pack = {"name": name, "version": "0.1.0", "profiles": profiles}
    output_path.write_text(yaml.safe_dump(pack, sort_keys=False, allow_unicode=True))
    return {
        "profiles_total": len(profiles),
        "unsupported_total": len(unsupported),
        "output": str(output_path),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Compile normalized public corpus into a replay pack")
    parser.add_argument("--input", required=True, help="Path to normalized public_cases JSONL")
    parser.add_argument("--output", required=True, help="Output replay pack YAML")
    parser.add_argument("--name", default="compiled-public-pack", help="Pack name")
    args = parser.parse_args()

    result = compile_pack(Path(args.input), Path(args.output), args.name)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
