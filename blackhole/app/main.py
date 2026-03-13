from __future__ import annotations

import html
import json
import os
import secrets
import time
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import quote, urlencode, urlparse

from fastapi import Body, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response

from .matcher import match_request
from .models import ReplayProfile, ScoreRequest
from .pack_loader import load_pack
from .runtime import BlackholeRuntime

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PACK = str(PROJECT_ROOT / "output" / "combined-pack.yaml")
PACK_PATH = os.environ.get("BLACKHOLE_PACK", DEFAULT_PACK)

app = FastAPI(title="blackhole-mock-server", version="0.6.0")
runtime = BlackholeRuntime.from_pack_path(PACK_PATH)


UI_SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; base-uri 'none'",
    "Cache-Control": "no-store",
}


@app.middleware("http")
async def add_ui_security_headers(request: Request, call_next):
    response = await call_next(request)
    path = request.url.path
    if (
        path == "/"
        or path.startswith("/families/")
        or path == "/robots.txt"
        or path == "/sitemap.xml"
        or path.startswith("/__blackhole/profile/")
        or path.startswith("/__blackhole/entry/")
        or path in {"/__blackhole/health", "/__blackhole/profiles", "/__blackhole/truth", "/__blackhole/state"}
    ):
        for k, v in UI_SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
    return response


# -------- sample helpers --------

def _sample_value(param_name: str, vuln_class: str) -> str:
    low = vuln_class.lower()
    pname = param_name.lower()
    if "xss" in low:
        return "<script>alert(1)</script>"
    if pname in {"redirect_uri", "callback", "return_to"}:
        return "https://attacker.example/callback"
    if pname in {"target_url", "source_url", "url"}:
        return "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    if pname in {"client_id"}:
        return "demo-client"
    if pname in {"event"}:
        return "build.complete"
    if pname in {"job"}:
        return "contacts-sync"
    if pname in {"state"}:
        return "xyz"
    if "redirect" in low or pname in {"next", "target", "redirect"}:
        return "https://evil.example"
    if "sqli" in low or "sql" in low or "injection" in low:
        return "1'"
    if "csrf" in low and pname in {"email", "mail"}:
        return "attacker@evil.example"
    if "traversal" in low or pname in {"file", "path", "filename"}:
        return "../../../../etc/passwd"
    if "graphql" in low:
        return "{__schema{queryType{name}}}"
    if "ssrf" in low:
        return "http://169.254.169.254/latest/meta-data/"
    if "crypto" in low or "jwt" in low or pname == "token":
        return "eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ."
    if "secret" in low or "exposure" in low:
        return "test"
    return "test"



def _profile_path(profile: ReplayProfile) -> str:
    return profile.matcher.path or profile.matcher.path_regex or profile.matcher.path_template or "/"



def _sample_query_for_profile(profile: ReplayProfile) -> dict[str, str]:
    return {key: _sample_value(key, profile.truth.vuln_class) for key in profile.matcher.query.keys()}



def _sample_path_for_profile(profile: ReplayProfile) -> str:
    path = profile.matcher.path or "/"
    params = _sample_query_for_profile(profile)
    return f"{path}?{urlencode(params)}" if params else path



def _sample_curl_for_profile(profile: ReplayProfile) -> str:
    matcher = profile.matcher
    method = matcher.method.upper()
    path = matcher.path or "/"
    base = '${BASE_URL:-http://localhost:8010}'
    if method == "GET":
        sample = _sample_path_for_profile(profile)
        cmd = f"curl -i '{base}{sample}'"
        if matcher.headers:
            for k in matcher.headers.keys():
                sample_val = "https://attacker.example" if k.lower() == "origin" else "test"
                cmd += f" -H '{k}: {sample_val}'"
        return cmd
    if method == "POST" and matcher.json_fields:
        payload = {field.path.split('.')[-1]: _sample_value(field.path.split('.')[-1], profile.truth.vuln_class) for field in matcher.json_fields}
        import json
        return f"curl -i -X POST '{base}{path}' -H 'Content-Type: application/json' --data '{json.dumps(payload)}'"
    if method == "POST" and matcher.body_contains:
        if "graphql" in profile.truth.vuln_class:
            body = '{"query":"{__schema{queryType{name}}}"}'
            content_type = "application/json"
        elif "xml" in path or "xxe" in profile.truth.vuln_class:
            body = '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><root>&xxe;</root>'
            content_type = "application/xml"
        elif "upload" in path:
            return (
                f"curl -i -X POST '{base}{path}' "
                "-H 'Content-Type: multipart/form-data; boundary=----bh' "
                r"--data-binary $'------bh\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\nContent-Type: application/octet-stream\r\n\r\n<?php phpinfo(); ?>\r\n------bh--\r\n'"
            )
        else:
            body = "test"
            content_type = "application/x-www-form-urlencoded"
        return f"curl -i -X POST '{base}{path}' -H 'Content-Type: {content_type}' --data '{body}'"
    return f"curl -i -X {method} '{base}{path}'"



def _family(profile: ReplayProfile) -> str:
    return profile.truth.north_star_section or (profile.tags[0] if profile.tags else "other")



def _method_badge(profile: ReplayProfile) -> str:
    return profile.matcher.method.upper()



def _discovery_path(profile: ReplayProfile) -> str:
    return f"/__blackhole/entry/{quote(profile.id, safe='')}"



def _display_link_for_profile(profile: ReplayProfile) -> tuple[str, str]:
    # direct GET cases should stay directly clickable; everything else gets a discovery page
    if profile.matcher.method.upper() == "GET" and not profile.matcher.headers and not profile.matcher.cookies and not profile.matcher.json_fields and not profile.matcher.body_contains and not profile.matcher.body_regex:
        return _sample_path_for_profile(profile), "open test case"
    return _discovery_path(profile), "open discovery page"



def _profiles_by_family() -> dict[str, list[ReplayProfile]]:
    families: dict[str, list[ReplayProfile]] = defaultdict(list)
    for p in runtime.profiles:
        families[_family(p)].append(p)
    return {k: sorted(v, key=lambda p: (p.title.lower(), p.id)) for k, v in families.items()}



def _render_cards(profiles: list[ReplayProfile]) -> str:
    cards: list[str] = []
    for profile in profiles:
        sample_href, sample_label = _display_link_for_profile(profile)
        curl_cmd = html.escape(_sample_curl_for_profile(profile))
        path_desc = html.escape(_profile_path(profile))
        tags = " ".join(f'<span class="tag">{html.escape(tag)}</span>' for tag in profile.tags)
        cards.append(
            f"""
            <div class="card" data-title="{html.escape(profile.title.lower())}" data-family="{html.escape(_family(profile))}" data-method="{html.escape(_method_badge(profile))}">
              <div class="card-head">
                <h3>{html.escape(profile.title)}</h3>
                <div class="meta">{html.escape(profile.truth.vuln_class)} · <span class="method">{html.escape(_method_badge(profile))}</span> {path_desc}</div>
              </div>
              <div class="links">
                <a href="{html.escape(sample_href)}">{html.escape(sample_label)}</a> · <a href="/__blackhole/profile/{html.escape(profile.id)}">profile json</a>
              </div>
              <div class="tags">{tags}</div>
              <pre>{curl_cmd}</pre>
            </div>
            """
        )
    return "".join(cards)



def _page_shell(title: str, intro_html: str, body_html: str, method_counts: Counter | None = None) -> str:
    method_summary = ""
    if method_counts:
        method_summary = " · ".join(f"{html.escape(name)}: {count}" for name, count in sorted(method_counts.items()))
    return f"""
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8">
        <meta name="robots" content="index,follow">
        <title>{html.escape(title)}</title>
        <style>
          body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 2rem; line-height: 1.4; background: #fafafa; color: #111; }}
          .top {{ margin-bottom: 1.5rem; }}
          .muted {{ color: #666; }}
          .summary {{ display:flex; flex-wrap:wrap; gap:.75rem; margin:.75rem 0 1rem; color:#444; }}
          .toolbar {{ display:flex; flex-wrap:wrap; gap:.75rem; align-items:center; margin:1rem 0 1.25rem; }}
          .toolbar input, .toolbar select {{ padding:.55rem .7rem; border:1px solid #ccc; border-radius:10px; background:white; }}
          .chips {{ display:flex; flex-wrap:wrap; gap:.45rem; margin: .75rem 0 1rem; }}
          .chip {{ display:inline-flex; gap:.35rem; align-items:center; border:1px solid #ddd; border-radius:999px; padding:.3rem .6rem; background:white; color:#333; }}
          .chip span {{ color:#666; }}
          .family-block {{ margin: 1.5rem 0 2rem; }}
          .family-block h2 {{ margin:.2rem 0 .8rem; font-size:1.15rem; }}
          .count {{ color:#666; font-weight:normal; font-size:.95rem; }}
          .grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(360px, 1fr)); gap: 1rem; }}
          .card {{ background: white; border: 1px solid #ddd; border-radius: 10px; padding: 1rem; box-shadow: 0 1px 2px rgba(0,0,0,.04); }}
          .card h3 {{ margin: 0 0 .35rem; font-size: 1.02rem; }}
          .meta {{ color: #555; font-size: .92rem; margin-bottom: .6rem; }}
          .method {{ display:inline-block; padding:.08rem .35rem; border:1px solid #ddd; border-radius:999px; font-size:.78rem; color:#444; }}
          .links {{ margin-bottom: .6rem; }}
          .tag {{ display: inline-block; font-size: .8rem; padding: .15rem .45rem; border: 1px solid #ddd; border-radius: 999px; margin: .1rem .2rem .1rem 0; color: #444; }}
          pre, code, textarea {{ background: #f6f8fa; }}
          pre {{ padding: .75rem; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; word-break: break-word; }}
          a {{ color: #0b57d0; text-decoration: none; }}
          a:hover {{ text-decoration: underline; }}
          .hidden {{ display:none !important; }}
          .panel {{ background:white; border:1px solid #ddd; border-radius:10px; padding:1rem; margin:1rem 0; }}
          input[type=text], textarea {{ width:100%; max-width:100%; padding:.6rem .7rem; border:1px solid #ccc; border-radius:8px; }}
          textarea {{ min-height: 10rem; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }}
          button {{ padding:.55rem .9rem; border:1px solid #bbb; border-radius:8px; background:#fff; cursor:pointer; }}
          ul.pathlist li {{ margin:.25rem 0; }}
        </style>
      </head>
      <body>
        <div class="top">
          <h1>{html.escape(title)}</h1>
          <p class="muted">Pack: {html.escape(runtime.pack.name)} · Profiles: {len(runtime.profiles)}</p>
          <p><a href="/">home</a> · <a href="/sitemap.xml">sitemap</a> · <a href="/__blackhole/health">health</a> · <a href="/__blackhole/profiles">profiles</a> · <a href="/__blackhole/truth">truth</a></p>
          {intro_html}
          <div class="summary"><span>Methods: {method_summary}</span></div>
        </div>
        {body_html}
      </body>
    </html>
    """


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    family_map = _profiles_by_family()
    family_counts = Counter({family: len(items) for family, items in family_map.items()})
    method_counts = Counter(_method_badge(p) for p in runtime.profiles)

    family_links = " ".join(
        f'<a class="chip" href="/families/{quote(name, safe="")}">{html.escape(name)} <span>{count}</span></a>'
        for name, count in sorted(family_counts.items(), key=lambda item: (-item[1], item[0]))
    )

    sections: list[str] = []
    for family in sorted(family_map.keys(), key=lambda item: (-family_counts[item], item)):
        family_profiles = family_map[family]
        sections.append(
            f"""
            <section class="family-block">
              <h2><a href="/families/{quote(family, safe='')}">{html.escape(family)}</a> <span class="count">{len(family_profiles)}</span></h2>
              <div class="grid">{_render_cards(family_profiles[:16])}</div>
              <p class="muted"><a href="/families/{quote(family, safe='')}">browse all {len(family_profiles)} {html.escape(family)} profiles</a></p>
            </section>
            """
        )

    intro = (
        "<p>This build is crawler-oriented: every profile now has a crawlable entry point. "
        "Direct GET cases link to the live endpoint; POST-only or header-driven cases link to a discovery page with a form or the actual endpoint path. "
        "Family navigation now uses real URLs instead of hash anchors.</p>"
        f'<div class="chips">{family_links}</div>'
    )
    return _page_shell("Blackhole Mock Server", intro, "".join(sections), method_counts)


@app.get("/families/{family}", response_class=HTMLResponse)
def family_page(family: str) -> str:
    family_map = _profiles_by_family()
    if family not in family_map:
        raise HTTPException(status_code=404, detail="family not found")
    profiles = family_map[family]
    method_counts = Counter(_method_badge(p) for p in profiles)
    intro = f"<p>Family <strong>{html.escape(family)}</strong>. Every card below links either to a direct test case or to a discovery page that exposes the endpoint to a crawler-friendly form.</p>"
    body = f'<div class="grid">{_render_cards(profiles)}</div>'
    return _page_shell(f"Blackhole Family: {family}", intro, body, method_counts)


@app.get("/sitemap.xml")
def sitemap() -> Response:
    urls: list[str] = ["/", "/__blackhole/health", "/__blackhole/profiles", "/__blackhole/truth"]
    family_map = _profiles_by_family()
    for family in sorted(family_map.keys()):
        urls.append(f"/families/{quote(family, safe='')}")
    for profile in runtime.profiles:
        href, _ = _display_link_for_profile(profile)
        urls.append(href)
        if _discovery_path(profile) not in urls:
            urls.append(_discovery_path(profile))
    items = "".join(f"<url><loc>{html.escape(url)}</loc></url>" for url in dict.fromkeys(urls))
    xml = f'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{items}</urlset>'
    return Response(content=xml, media_type="application/xml")


@app.get("/robots.txt")
async def robots(request: Request):
    content = "User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /backup/\nDisallow: /phpmyadmin\nDisallow: /secret-debug\nSitemap: /sitemap.xml\n"
    response = PlainTextResponse(content)
    return await _finalize_custom_response(request, response, "builtin-robots-sensitive")


@app.get("/__blackhole/profile/{profile_id}")
def profile_detail(profile_id: str) -> dict:
    for profile in runtime.profiles:
        if profile.id == profile_id:
            return profile.model_dump(mode="json")
    raise HTTPException(status_code=404, detail="profile not found")



def _render_form_for_profile(profile: ReplayProfile) -> str:
    matcher = profile.matcher
    method = matcher.method.upper()
    path = html.escape(matcher.path or "/")
    query_fields = _sample_query_for_profile(profile)

    if method == "GET":
        inputs = "".join(
            f'<label>{html.escape(name)}<input type="text" name="{html.escape(name)}" value="{html.escape(value)}"></label><br>'
            for name, value in query_fields.items()
        ) or '<p class="muted">No parameters required.</p>'
        header_note = ""
        if matcher.headers:
            header_note = f"<p class=\"muted\">This profile also expects headers: {html.escape(', '.join(matcher.headers.keys()))}. A crawler can still reach the endpoint path directly here.</p>"
        return f'<div class="panel"><h3>Endpoint discovery</h3><p>Actual endpoint: <a href="{path}">{path}</a></p>{header_note}<form method="GET" action="{path}">{inputs}<button type="submit">Send GET request</button></form></div>'

    if method == "POST":
        if matcher.json_fields or "graphql" in profile.truth.vuln_class:
            if matcher.json_fields:
                fields = {field.path.split('.')[-1]: _sample_value(field.path.split('.')[-1], profile.truth.vuln_class) for field in matcher.json_fields}
            else:
                fields = {"query": _sample_value("query", profile.truth.vuln_class)}
            import json
            body = json.dumps(fields, indent=2)
            return (
                f'<div class="panel"><h3>POST endpoint discovery</h3><p>Actual endpoint: <a href="{path}">{path}</a></p>'
                f'<form method="POST" action="{path}" enctype="text/plain">'
                f'<textarea name="payload">{html.escape(body)}</textarea>'
                '<p class="muted">This form exists mainly so crawlers see the endpoint path. Use the sample curl below for exact JSON requests.</p>'
                '<button type="submit">Send POST request</button></form></div>'
            )
        if "xxe" in profile.truth.vuln_class:
            body = '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><root>&xxe;</root>'
            return (
                f'<div class="panel"><h3>POST endpoint discovery</h3><p>Actual endpoint: <a href="{path}">{path}</a></p>'
                f'<form method="POST" action="{path}" enctype="text/plain">'
                f'<textarea name="xml">{html.escape(body)}</textarea>'
                '<button type="submit">Send POST request</button></form></div>'
            )
        if "upload" in _profile_path(profile) or "file-upload" in profile.truth.north_star_section:
            return (
                f'<div class="panel"><h3>Upload endpoint discovery</h3><p>Actual endpoint: <a href="{path}">{path}</a></p>'
                f'<form method="POST" action="{path}" enctype="multipart/form-data">'
                '<input type="file" name="file"> <button type="submit">Upload</button></form></div>'
            )
        body = matcher.body_contains or "test"
        return (
            f'<div class="panel"><h3>POST endpoint discovery</h3><p>Actual endpoint: <a href="{path}">{path}</a></p>'
            f'<form method="POST" action="{path}"><textarea name="payload">{html.escape(body)}</textarea><button type="submit">Send POST request</button></form></div>'
        )

    return f'<div class="panel"><p>Actual endpoint: <a href="{path}">{path}</a></p></div>'


@app.get("/__blackhole/entry/{profile_id}", response_class=HTMLResponse)
def profile_entry(profile_id: str) -> str:
    for profile in runtime.profiles:
        if profile.id == profile_id:
            intro = (
                f"<p>{html.escape(profile.title)} · <strong>{html.escape(profile.truth.vuln_class)}</strong></p>"
                f"<p>This is a crawler-friendly discovery page for the endpoint <code>{html.escape(_profile_path(profile))}</code>.</p>"
            )
            body = (
                f'<div class="panel"><p><a href="{html.escape(_profile_path(profile))}">Open actual endpoint path</a></p>'
                f'<pre>{html.escape(_sample_curl_for_profile(profile))}</pre></div>'
                f'{_render_form_for_profile(profile)}'
            )
            return _page_shell(f"Entry: {profile.title}", intro, body)
    raise HTTPException(status_code=404, detail="profile not found")




# -------- custom second-order built-in flows --------

def _builtin_profile(profile_id: str):
    profile = runtime.profile_by_id(profile_id)
    if not profile:
        raise HTTPException(status_code=500, detail=f"builtin profile missing: {profile_id}")
    return profile


def _truth_hint_script(profile_id: str) -> str:
    profile = _builtin_profile(profile_id)
    hint = {
        "profile_id": profile.id,
        "case_id": profile.case_id,
        "expected_family": profile.truth.north_star_section,
        "expected_vuln_class": profile.truth.vuln_class,
        "expected_evidence_type": profile.truth.positive_evidence,
        "must_not_claim_families": profile.truth.must_not_claim,
        "second_order": profile.truth.second_order,
        "second_order_sink": profile.truth.second_order_sink,
    }
    return f'<script id="blackhole-truth" type="application/json">{html.escape(json.dumps(hint, sort_keys=True))}</script>'


async def _request_data(request: Request) -> dict:
    ctype = (request.headers.get("content-type") or "").lower()
    raw = await request.body()
    text_body = raw.decode("utf-8", errors="replace") if raw else ""
    if "application/json" in ctype:
        try:
            payload = json.loads(text_body) if text_body else {}
            return payload if isinstance(payload, dict) else {"payload": payload}
        except Exception:
            return {}
    if "application/x-www-form-urlencoded" in ctype:
        from urllib.parse import parse_qs
        parsed = parse_qs(text_body, keep_blank_values=True)
        return {k: (v[-1] if isinstance(v, list) and v else "") for k, v in parsed.items()}
    if "multipart/form-data" in ctype:
        form = await request.form()
        data = {k: str(v) for k, v in form.items()}
        if "payload" in data and data["payload"].strip().startswith("{"):
            try:
                maybe = json.loads(data["payload"])
                if isinstance(maybe, dict):
                    data.update(maybe)
            except Exception:
                pass
        return data
    if "text/plain" in ctype:
        data = {"payload": text_body}
        if text_body.strip().startswith("{"):
            try:
                maybe = json.loads(text_body)
                if isinstance(maybe, dict):
                    data.update(maybe)
            except Exception:
                pass
        return data
    return {}


def _looks_internal_url(target: str) -> bool:
    if not target:
        return False
    try:
        parsed = urlparse(target)
    except Exception:
        return False
    host = (parsed.hostname or "").lower()
    if parsed.scheme in {"file", "gopher", "dict"}:
        return True
    if host in {"localhost", "metadata", "metadata.google.internal"}:
        return True
    if host.startswith("127.") or host.startswith("10.") or host.startswith("192.168.") or host.startswith("169.254."):
        return True
    if host.startswith("172."):
        parts = host.split(".")
        if len(parts) > 1 and parts[1].isdigit() and 16 <= int(parts[1]) <= 31:
            return True
    return False


async def _finalize_custom_response(request: Request, response: Response, profile_id: str):
    profile = _builtin_profile(profile_id)
    client_id = runtime.get_client_id(request)
    response.set_cookie("bh_client_id", client_id, httponly=False)
    response.headers.setdefault("X-Blackhole-Profile", profile.id)
    response.headers.setdefault("X-Blackhole-Case", profile.case_id)
    await runtime.log_request(request, response.status_code, profile, client_id)
    return response


def _append_history(client_id: str, key: str, item: dict, limit: int = 20) -> list[dict]:
    history = list(runtime.state.recall(client_id, key, []) or [])
    history.insert(0, item)
    history = history[:limit]
    runtime.state.remember(client_id, key, history)
    return history


def _json_or_html(request: Request, html_body: str, json_body: dict, *, title: str = "Blackhole") -> Response:
    accept = (request.headers.get("accept") or "").lower()
    if "application/json" in accept or request.query_params.get("format") == "json":
        return JSONResponse(json_body)
    return HTMLResponse(_page_shell(title, "", html_body))


@app.get("/integrations/webhooks", response_class=HTMLResponse)
async def webhook_lab() -> str:
    body = f"""
    <section class="panel"><h2>Webhook second-order flow</h2>
      <p>Configure a target URL, then trigger an event later. The vulnerable flow uses the stored URL when the event fires. The safe flow blocks internal targets at trigger time.</p>
      {_truth_hint_script('builtin-webhook-trigger')}
      <form method="POST" action="/api/webhooks/register">
        <label>event<input type="text" name="event" value="build.complete"></label><br>
        <label>target_url<input type="text" name="target_url" value="http://169.254.169.254/latest/meta-data/iam/security-credentials/"></label><br>
        <button type="submit">Register vulnerable webhook</button>
      </form>
      <form method="POST" action="/api/webhooks/register-safe" style="margin-top:1rem">
        <label>event<input type="text" name="event" value="build.complete"></label><br>
        <label>target_url<input type="text" name="target_url" value="http://169.254.169.254/latest/meta-data/iam/security-credentials/"></label><br>
        <button type="submit">Register safe webhook</button>
      </form>
      <p><a href="/api/webhooks/trigger?event=build.complete">Trigger vulnerable delivery</a> · <a href="/api/webhooks/trigger-safe?event=build.complete">Trigger safe delivery</a> · <a href="/integrations/webhooks/history">View delivery history</a></p>
    </section>
    """
    return _page_shell("Webhook flow", "<p>Crawler-friendly webhook/import-style second-order lab.</p>", body)


@app.post("/api/webhooks/register")
async def webhook_register(request: Request):
    data = await _request_data(request)
    client_id = runtime.get_client_id(request)
    target_url = data.get("target_url") or data.get("url") or "http://169.254.169.254/latest/meta-data/"
    event = data.get("event") or "build.complete"
    hooks = list(runtime.state.recall(client_id, "webhooks_vuln", []) or [])
    hooks.append({"target_url": target_url, "event": event, "created_at": int(time.time())})
    runtime.state.remember(client_id, "webhooks_vuln", hooks)
    runtime.state.set_state(client_id, "webhook-flow", "WEBHOOK_REGISTERED")
    response = JSONResponse({"registered": True, "mode": "vulnerable", "target_url": target_url, "event": event}, status_code=201)
    return await _finalize_custom_response(request, response, "builtin-webhook-register")


@app.post("/api/webhooks/register-safe")
async def webhook_register_safe(request: Request):
    data = await _request_data(request)
    client_id = runtime.get_client_id(request)
    target_url = data.get("target_url") or data.get("url") or "http://169.254.169.254/latest/meta-data/"
    event = data.get("event") or "build.complete"
    hooks = list(runtime.state.recall(client_id, "webhooks_safe", []) or [])
    hooks.append({"target_url": target_url, "event": event, "created_at": int(time.time())})
    runtime.state.remember(client_id, "webhooks_safe", hooks)
    runtime.state.set_state(client_id, "webhook-safe-flow", "WEBHOOK_REGISTERED")
    response = JSONResponse({"registered": True, "mode": "safe", "target_url": target_url, "event": event}, status_code=201)
    return await _finalize_custom_response(request, response, "builtin-webhook-register-safe")


@app.get("/api/webhooks/trigger")
async def webhook_trigger(request: Request, event: str = "build.complete"):
    client_id = runtime.get_client_id(request)
    hooks = list(runtime.state.recall(client_id, "webhooks_vuln", []) or [])
    hook = next((h for h in reversed(hooks) if h.get("event") == event), None)
    if not hook:
        response = JSONResponse({"error": "no webhook configured for event", "event": event}, status_code=404)
        return await _finalize_custom_response(request, response, "builtin-webhook-trigger")
    target_url = hook["target_url"]
    internal = _looks_internal_url(target_url)
    result = {
        "event": event,
        "target_url": target_url,
        "delivered": True,
        "second_order": True,
        "internal_fetch": internal,
        "response_excerpt": "role=admin\nsecret_key=AKIA...\ninstance-id=i-blackhole" if internal else "200 OK from external webhook receiver",
    }
    _append_history(client_id, "webhook_history", {"mode": "vulnerable", **result})
    runtime.state.set_state(client_id, "webhook-flow", "DELIVERED")
    response = JSONResponse(result)
    return await _finalize_custom_response(request, response, "builtin-webhook-trigger")


@app.get("/api/webhooks/trigger-safe")
async def webhook_trigger_safe(request: Request, event: str = "build.complete"):
    client_id = runtime.get_client_id(request)
    hooks = list(runtime.state.recall(client_id, "webhooks_safe", []) or [])
    hook = next((h for h in reversed(hooks) if h.get("event") == event), None)
    if not hook:
        response = JSONResponse({"error": "no safe webhook configured for event", "event": event}, status_code=404)
        return await _finalize_custom_response(request, response, "builtin-webhook-trigger-safe")
    target_url = hook["target_url"]
    blocked = _looks_internal_url(target_url)
    result = {
        "event": event,
        "target_url": target_url,
        "delivered": not blocked,
        "blocked_by_policy": blocked,
        "response_excerpt": None if blocked else "200 OK from external webhook receiver",
    }
    _append_history(client_id, "webhook_history", {"mode": "safe", **result})
    runtime.state.set_state(client_id, "webhook-safe-flow", "BLOCKED" if blocked else "DELIVERED")
    response = JSONResponse(result, status_code=403 if blocked else 200)
    return await _finalize_custom_response(request, response, "builtin-webhook-trigger-safe")


@app.get("/integrations/webhooks/history", response_class=HTMLResponse)
async def webhook_history(request: Request) -> str:
    client_id = runtime.get_client_id(request)
    history = list(runtime.state.recall(client_id, "webhook_history", []) or [])
    items = "".join(f"<li><strong>{html.escape(item.get('mode','?'))}</strong> {html.escape(item.get('event',''))} → {html.escape(item.get('target_url',''))} · delivered={item.get('delivered')} blocked={item.get('blocked_by_policy', False)}</li>" for item in history) or "<li>No deliveries yet.</li>"
    body = f'<section class="panel"><h2>Webhook history</h2>{_truth_hint_script("builtin-webhook-trigger")}<ul>{items}</ul></section>'
    return _page_shell("Webhook delivery history", "<p>Observe whether the stored URL was later dereferenced.</p>", body)


@app.get("/imports/remote", response_class=HTMLResponse)
async def import_lab() -> str:
    body = f"""
    <section class="panel"><h2>Remote import second-order flow</h2>
      <p>Store a remote import source, then execute the import later. The vulnerable flow allows internal URLs and local file schemes. The safe flow blocks them.</p>
      {_truth_hint_script('builtin-import-run')}
      <form method="POST" action="/api/imports/configure">
        <label>job<input type="text" name="job" value="contacts-sync"></label><br>
        <label>source_url<input type="text" name="source_url" value="file:///etc/passwd"></label><br>
        <button type="submit">Configure vulnerable import</button>
      </form>
      <form method="POST" action="/api/imports/configure-safe" style="margin-top:1rem">
        <label>job<input type="text" name="job" value="contacts-sync"></label><br>
        <label>source_url<input type="text" name="source_url" value="file:///etc/passwd"></label><br>
        <button type="submit">Configure safe import</button>
      </form>
      <p><a href="/api/imports/run?job=contacts-sync">Run vulnerable import</a> · <a href="/api/imports/run-safe?job=contacts-sync">Run safe import</a> · <a href="/imports/history">View import history</a></p>
    </section>
    """
    return _page_shell("Remote import flow", "<p>Crawler-friendly import/webhook-style second-order lab.</p>", body)


@app.post("/api/imports/configure")
async def import_configure(request: Request):
    data = await _request_data(request)
    client_id = runtime.get_client_id(request)
    source_url = data.get("source_url") or data.get("url") or "file:///etc/passwd"
    job = data.get("job") or "contacts-sync"
    jobs = list(runtime.state.recall(client_id, "imports_vuln", []) or [])
    jobs.append({"source_url": source_url, "job": job, "created_at": int(time.time())})
    runtime.state.remember(client_id, "imports_vuln", jobs)
    runtime.state.set_state(client_id, "import-flow", "IMPORT_CONFIGURED")
    response = JSONResponse({"configured": True, "mode": "vulnerable", "source_url": source_url, "job": job}, status_code=201)
    return await _finalize_custom_response(request, response, "builtin-import-configure")


@app.post("/api/imports/configure-safe")
async def import_configure_safe(request: Request):
    data = await _request_data(request)
    client_id = runtime.get_client_id(request)
    source_url = data.get("source_url") or data.get("url") or "file:///etc/passwd"
    job = data.get("job") or "contacts-sync"
    jobs = list(runtime.state.recall(client_id, "imports_safe", []) or [])
    jobs.append({"source_url": source_url, "job": job, "created_at": int(time.time())})
    runtime.state.remember(client_id, "imports_safe", jobs)
    runtime.state.set_state(client_id, "import-safe-flow", "IMPORT_CONFIGURED")
    response = JSONResponse({"configured": True, "mode": "safe", "source_url": source_url, "job": job}, status_code=201)
    return await _finalize_custom_response(request, response, "builtin-import-configure-safe")


@app.get("/api/imports/run")
async def import_run(request: Request, job: str = "contacts-sync"):
    client_id = runtime.get_client_id(request)
    jobs = list(runtime.state.recall(client_id, "imports_vuln", []) or [])
    item = next((h for h in reversed(jobs) if h.get("job") == job), None)
    if not item:
        response = JSONResponse({"error": "no import configured", "job": job}, status_code=404)
        return await _finalize_custom_response(request, response, "builtin-import-run")
    source_url = item["source_url"]
    internal = _looks_internal_url(source_url)
    local_file = source_url.lower().startswith("file://")
    result = {
        "job": job,
        "source_url": source_url,
        "imported": True,
        "second_order": True,
        "internal_fetch": internal,
        "local_file_read": local_file,
        "records": 2 if (internal or local_file) else 15,
        "preview": "root:x:0:0:root:/root:/bin/bash" if local_file else ("instance-id=i-blackhole" if internal else "email,name\nalice@example.com,Alice"),
    }
    runtime.state.remember(client_id, "last_import_result", result)
    _append_history(client_id, "import_history", {"mode": "vulnerable", **result})
    runtime.state.set_state(client_id, "import-flow", "IMPORT_RAN")
    response = JSONResponse(result)
    return await _finalize_custom_response(request, response, "builtin-import-run")


@app.get("/api/imports/run-safe")
async def import_run_safe(request: Request, job: str = "contacts-sync"):
    client_id = runtime.get_client_id(request)
    jobs = list(runtime.state.recall(client_id, "imports_safe", []) or [])
    item = next((h for h in reversed(jobs) if h.get("job") == job), None)
    if not item:
        response = JSONResponse({"error": "no safe import configured", "job": job}, status_code=404)
        return await _finalize_custom_response(request, response, "builtin-import-run-safe")
    source_url = item["source_url"]
    blocked = _looks_internal_url(source_url)
    local_file = source_url.lower().startswith("file://")
    result = {
        "job": job,
        "source_url": source_url,
        "imported": not blocked,
        "blocked_by_policy": blocked,
        "local_file_read": False,
        "preview": None if blocked else "email,name\nalice@example.com,Alice",
    }
    runtime.state.remember(client_id, "last_import_result_safe", result)
    _append_history(client_id, "import_history", {"mode": "safe", **result})
    runtime.state.set_state(client_id, "import-safe-flow", "BLOCKED" if blocked or local_file else "IMPORT_RAN")
    response = JSONResponse(result, status_code=403 if blocked or local_file else 200)
    return await _finalize_custom_response(request, response, "builtin-import-run-safe")


@app.get("/imports/history", response_class=HTMLResponse)
async def import_history(request: Request) -> str:
    client_id = runtime.get_client_id(request)
    history = list(runtime.state.recall(client_id, "import_history", []) or [])
    items = "".join(f"<li><strong>{html.escape(item.get('mode','?'))}</strong> {html.escape(item.get('job',''))} ← {html.escape(item.get('source_url',''))} · imported={item.get('imported')} blocked={item.get('blocked_by_policy', False)}</li>" for item in history) or "<li>No imports yet.</li>"
    body = f'<section class="panel"><h2>Import history</h2>{_truth_hint_script("builtin-import-run")}<ul>{items}</ul></section>'
    return _page_shell("Import history", "<p>Observe whether the stored import source was later dereferenced.</p>", body)


@app.get("/imports/last-result")
async def import_last_result(request: Request):
    client_id = runtime.get_client_id(request)
    result = runtime.state.recall(client_id, "last_import_result") or runtime.state.recall(client_id, "last_import_result_safe") or {"message": "no import result yet"}
    response = JSONResponse(result)
    return await _finalize_custom_response(request, response, "builtin-import-run")


@app.get("/oauth/lab", response_class=HTMLResponse)
async def oauth_lab() -> str:
    body = f"""
    <section class="panel"><h2>OAuth redirect_uri second-order flow</h2>
      <p>Register a client redirect URI, then later run authorization. The vulnerable flow will happily issue a code to an attacker-controlled redirect URI. The safe flow requires an exact redirect URI match.</p>
      {_truth_hint_script('builtin-oauth-authorize')}
      <form method="POST" action="/oauth/register-client">
        <label>client_id<input type="text" name="client_id" value="demo-client"></label><br>
        <label>redirect_uri<input type="text" name="redirect_uri" value="https://attacker.example/callback"></label><br>
        <button type="submit">Register client</button>
      </form>
      <p><a href="/oauth/authorize?client_id=demo-client&redirect_uri=https://attacker.example/callback&state=xyz">Authorize vulnerable flow</a></p>
      <p><a href="/oauth/authorize-safe?client_id=demo-client&redirect_uri=https://attacker.example/callback&state=xyz">Authorize safe flow</a></p>
      <p><a href="/oauth/audit">View OAuth audit log</a></p>
    </section>
    """
    return _page_shell("OAuth flow", "<p>Crawler-friendly OAuth-style second-order lab.</p>", body)


@app.post("/oauth/register-client")
async def oauth_register_client(request: Request):
    data = await _request_data(request)
    client_id = runtime.get_client_id(request)
    reg_client_id = data.get("client_id") or "demo-client"
    redirect_uri = data.get("redirect_uri") or "https://attacker.example/callback"
    clients = dict(runtime.state.recall(client_id, "oauth_clients", {}) or {})
    clients[reg_client_id] = {"redirect_uri": redirect_uri, "registered_at": int(time.time())}
    runtime.state.remember(client_id, "oauth_clients", clients)
    runtime.state.set_state(client_id, "oauth-flow", "CLIENT_REGISTERED")
    response = JSONResponse({"registered": True, "client_id": reg_client_id, "redirect_uri": redirect_uri}, status_code=201)
    return await _finalize_custom_response(request, response, "builtin-oauth-register-client")


@app.get("/oauth/authorize")
async def oauth_authorize(request: Request, client_id: str = "demo-client", redirect_uri: str | None = None, state: str = "xyz"):
    cid = runtime.get_client_id(request)
    clients = dict(runtime.state.recall(cid, "oauth_clients", {}) or {})
    registered = clients.get(client_id, {})
    target = redirect_uri or registered.get("redirect_uri")
    if not target:
        response = JSONResponse({"error": "client not registered", "client_id": client_id}, status_code=404)
        return await _finalize_custom_response(request, response, "builtin-oauth-authorize")
    code = f"bhcode-{secrets.token_hex(4)}"
    sep = "&" if "?" in target else "?"
    location = f"{target}{sep}code={code}&state={quote(state)}"
    runtime.state.remember(cid, "oauth_last_code", {"client_id": client_id, "redirect_uri": target, "code": code, "state": state})
    _append_history(cid, "oauth_audit", {"mode": "vulnerable", "client_id": client_id, "redirect_uri": target, "code": code, "state": state})
    runtime.state.set_state(cid, "oauth-flow", "CODE_ISSUED")
    response = RedirectResponse(location, status_code=302)
    return await _finalize_custom_response(request, response, "builtin-oauth-authorize")


@app.get("/oauth/authorize-safe")
async def oauth_authorize_safe(request: Request, client_id: str = "demo-client", redirect_uri: str | None = None, state: str = "xyz"):
    cid = runtime.get_client_id(request)
    clients = dict(runtime.state.recall(cid, "oauth_clients", {}) or {})
    registered = clients.get(client_id, {})
    registered_uri = registered.get("redirect_uri")
    if not registered_uri:
        response = JSONResponse({"error": "client not registered", "client_id": client_id}, status_code=404)
        return await _finalize_custom_response(request, response, "builtin-oauth-authorize-safe")
    if redirect_uri and redirect_uri != registered_uri:
        result = {"error": "redirect_uri mismatch", "client_id": client_id, "registered_redirect_uri": registered_uri, "provided_redirect_uri": redirect_uri, "exact_match_required": True}
        _append_history(cid, "oauth_audit", {"mode": "safe", **result})
        runtime.state.set_state(cid, "oauth-safe-flow", "REDIRECT_REJECTED")
        response = JSONResponse(result, status_code=400)
        return await _finalize_custom_response(request, response, "builtin-oauth-authorize-safe")
    code = f"bhcode-{secrets.token_hex(4)}"
    sep = "&" if "?" in registered_uri else "?"
    location = f"{registered_uri}{sep}code={code}&state={quote(state)}"
    _append_history(cid, "oauth_audit", {"mode": "safe", "client_id": client_id, "redirect_uri": registered_uri, "code": code, "state": state})
    runtime.state.set_state(cid, "oauth-safe-flow", "CODE_ISSUED")
    response = RedirectResponse(location, status_code=302)
    return await _finalize_custom_response(request, response, "builtin-oauth-authorize-safe")


@app.get("/oauth/audit", response_class=HTMLResponse)
async def oauth_audit(request: Request) -> str:
    cid = runtime.get_client_id(request)
    clients = dict(runtime.state.recall(cid, "oauth_clients", {}) or {})
    audit = list(runtime.state.recall(cid, "oauth_audit", []) or [])
    client_items = "".join(f"<li>{html.escape(k)} → {html.escape(v.get('redirect_uri',''))}</li>" for k,v in clients.items()) or "<li>No clients registered.</li>"
    audit_items = "".join(f"<li><strong>{html.escape(item.get('mode','?'))}</strong> {html.escape(item.get('client_id',''))} → {html.escape(item.get('redirect_uri',''))} code={html.escape(item.get('code',''))}</li>" for item in audit) or "<li>No codes issued yet.</li>"
    body = f'<section class="panel"><h2>Registered clients</h2><ul>{client_items}</ul></section><section class="panel"><h2>Authorization audit</h2>{_truth_hint_script("builtin-oauth-authorize")}<ul>{audit_items}</ul></section>'
    return _page_shell("OAuth audit", "<p>Observe whether codes are issued to the registered or attacker-supplied redirect URI.</p>", body)




# -------- baseline / legacy built-in flows --------

BASELINE_USERS = {"admin": "admin123", "alice": "Summer2026!", "bob": "Welcome1!"}


def _login_page(title: str, action: str, hint_profile: str, intro: str) -> str:
    body = f"""
    <section class="panel"><h2>{html.escape(title)}</h2>
      <p>{html.escape(intro)}</p>
      {_truth_hint_script(hint_profile)}
      <form method="POST" action="{html.escape(action)}">
        <label>username<input type="text" name="username" value="admin"></label><br>
        <label>password<input type="password" name="password" value="admin123"></label><br>
        <button type="submit">Submit</button>
      </form>
      <p><a href="/account/recover">password recovery</a> · <a href="/account/recover-safe">safe password recovery</a></p>
    </section>
    """
    return _page_shell(title, "<p>Baseline auth discovery and brute-force behavior.</p>", body)


@app.get("/login", response_class=HTMLResponse)
async def login_page() -> str:
    return _login_page(
        "Weak form login",
        "/login",
        "builtin-form-login-weak",
        "This branch leaks whether a username exists and never locks out failed attempts.",
    )


@app.get("/login-safe", response_class=HTMLResponse)
async def login_safe_page() -> str:
    return _login_page(
        "Safe form login control",
        "/login-safe",
        "builtin-form-login-safe",
        "This branch returns generic failures and locks after repeated bad attempts.",
    )


@app.post("/login")
async def login_weak(request: Request):
    data = await _request_data(request)
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    client_id = runtime.get_client_id(request)
    known = username in BASELINE_USERS
    if not known:
        response = JSONResponse({"ok": False, "error": "user not found", "username_exists": False}, status_code=404)
        return await _finalize_custom_response(request, response, "builtin-form-login-weak")
    fails = int(runtime.state.recall(client_id, f"weak_login_fail:{username}", 0) or 0)
    if password == BASELINE_USERS[username]:
        runtime.state.remember(client_id, f"weak_login_fail:{username}", 0)
        runtime.state.remember(client_id, "auth_session", {"username": username, "role": "admin" if username == "admin" else "user"})
        response = JSONResponse({"ok": True, "username": username, "role": "admin" if username == "admin" else "user", "lockout": False}, status_code=200)
        return await _finalize_custom_response(request, response, "builtin-form-login-weak")
    fails += 1
    runtime.state.remember(client_id, f"weak_login_fail:{username}", fails)
    response = JSONResponse({"ok": False, "error": "invalid password", "username_exists": True, "attempts": fails, "remaining_attempts": "unlimited"}, status_code=401)
    return await _finalize_custom_response(request, response, "builtin-form-login-weak")


@app.post("/login-safe")
async def login_safe(request: Request):
    data = await _request_data(request)
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    client_id = runtime.get_client_id(request)
    counter_key = f"safe_login_fail:{username or 'anon'}"
    fails = int(runtime.state.recall(client_id, counter_key, 0) or 0)
    if fails >= 5:
        response = JSONResponse({"ok": False, "error": "account temporarily locked", "locked": True}, status_code=423)
        return await _finalize_custom_response(request, response, "builtin-form-login-safe")
    if username in BASELINE_USERS and password == BASELINE_USERS[username]:
        runtime.state.remember(client_id, counter_key, 0)
        runtime.state.remember(client_id, "auth_session_safe", {"username": username, "role": "admin" if username == "admin" else "user"})
        response = JSONResponse({"ok": True, "username": username}, status_code=200)
        return await _finalize_custom_response(request, response, "builtin-form-login-safe")
    fails += 1
    runtime.state.remember(client_id, counter_key, fails)
    status = 423 if fails >= 5 else 401
    payload = {"ok": False, "error": "invalid credentials"}
    if fails >= 5:
        payload["locked"] = True
    response = JSONResponse(payload, status_code=status)
    return await _finalize_custom_response(request, response, "builtin-form-login-safe")


@app.get("/account/recover", response_class=HTMLResponse)
async def recover_page() -> str:
    body = f"""
    <section class="panel"><h2>Password recovery enumeration</h2>
      <p>This branch returns different messages for existing and unknown users.</p>
      {_truth_hint_script('builtin-password-recovery-enum')}
      <form method="POST" action="/account/recover">
        <label>username<input type="text" name="username" value="admin"></label><br>
        <button type="submit">Recover</button>
      </form>
    </section>
    """
    return _page_shell("Password recovery", "<p>Baseline account recovery enumeration test.</p>", body)


@app.get("/account/recover-safe", response_class=HTMLResponse)
async def recover_safe_page() -> str:
    body = f"""
    <section class="panel"><h2>Password recovery control</h2>
      <p>This branch always returns the same message.</p>
      {_truth_hint_script('builtin-password-recovery-safe')}
      <form method="POST" action="/account/recover-safe">
        <label>username<input type="text" name="username" value="ghost"></label><br>
        <button type="submit">Recover</button>
      </form>
    </section>
    """
    return _page_shell("Password recovery control", "<p>Generic response baseline control.</p>", body)


@app.post("/account/recover")
async def recover_user(request: Request):
    data = await _request_data(request)
    username = (data.get("username") or data.get("email") or "").strip()
    exists = username in BASELINE_USERS
    if exists:
        response = JSONResponse({"recovery": "sent", "user_exists": True, "delivery": f"mailbox-for-{username}"}, status_code=200)
    else:
        response = JSONResponse({"error": "user not found", "user_exists": False}, status_code=404)
    return await _finalize_custom_response(request, response, "builtin-password-recovery-enum")


@app.post("/account/recover-safe")
async def recover_user_safe(request: Request):
    _ = await _request_data(request)
    response = JSONResponse({"accepted": True, "message": "If the account exists, recovery instructions will be sent."}, status_code=200)
    return await _finalize_custom_response(request, response, "builtin-password-recovery-safe")


@app.api_route("/api/methods", methods=["OPTIONS"])
async def methods_risky(request: Request):
    response = Response(status_code=204, headers={"Allow": "GET, POST, PUT, DELETE, TRACE, OPTIONS"})
    return await _finalize_custom_response(request, response, "builtin-options-risky")


@app.api_route("/api/methods-safe", methods=["OPTIONS"])
async def methods_safe(request: Request):
    response = Response(status_code=204, headers={"Allow": "GET, POST, OPTIONS"})
    return await _finalize_custom_response(request, response, "builtin-options-safe")


@app.api_route("/trace", methods=["TRACE"])
async def trace_enabled(request: Request):
    body = await request.body()
    lines = [f"TRACE {request.url.path} HTTP/1.1"]
    for k, v in request.headers.items():
        lines.append(f"{k}: {v}")
    if body:
        lines.append("")
        lines.append(body.decode("utf-8", errors="replace"))
    response = PlainTextResponse("\n".join(lines), media_type="message/http")
    return await _finalize_custom_response(request, response, "builtin-trace-enabled")


@app.api_route("/trace-safe", methods=["TRACE"])
async def trace_safe(request: Request):
    response = JSONResponse({"blocked": True, "method": "TRACE"}, status_code=405)
    return await _finalize_custom_response(request, response, "builtin-trace-disabled")


@app.api_route("/api/verb-tamper", methods=["POST"])
async def verb_tamper(request: Request):
    override = (request.headers.get("x-http-method-override") or "").upper()
    if override == "DELETE":
        response = JSONResponse({"deleted": True, "override_applied": True, "resource": "invoice-2026-0001"}, status_code=200)
    else:
        response = JSONResponse({"ok": True, "override_applied": False}, status_code=200)
    profile_id = "builtin-verb-tamper" if override == "DELETE" else "builtin-verb-tamper"
    return await _finalize_custom_response(request, response, profile_id)


@app.api_route("/api/verb-tamper-safe", methods=["POST"])
async def verb_tamper_safe(request: Request):
    override = (request.headers.get("x-http-method-override") or "").upper()
    if override == "DELETE":
        response = JSONResponse({"override_blocked": True, "allowed_methods": ["POST"]}, status_code=405)
    else:
        response = JSONResponse({"ok": True, "override_blocked": False}, status_code=200)
    return await _finalize_custom_response(request, response, "builtin-verb-tamper-safe")


@app.api_route("/uploads/{name:path}", methods=["PUT", "GET"])
async def writable_uploads(request: Request, name: str):
    client_id = runtime.get_client_id(request)
    uploads = dict(runtime.state.recall(client_id, "baseline_uploads", {}) or {})
    if request.method == "PUT":
        body = (await request.body()).decode("utf-8", errors="replace")
        uploads[name] = body
        runtime.state.remember(client_id, "baseline_uploads", uploads)
        response = JSONResponse({"stored": True, "location": f"/uploads/{name}", "size": len(body)}, status_code=201)
        return await _finalize_custom_response(request, response, "builtin-put-writable")
    if name in uploads:
        response = PlainTextResponse(uploads[name], status_code=200)
    else:
        response = PlainTextResponse("not found", status_code=404)
    response.set_cookie("bh_client_id", client_id, httponly=False)
    return response


@app.api_route("/uploads-safe/{name:path}", methods=["PUT", "GET"])
async def safe_uploads(request: Request, name: str):
    if request.method == "PUT":
        response = JSONResponse({"blocked_by_policy": True, "reason": "PUT disabled", "location": f"/uploads-safe/{name}"}, status_code=403)
        return await _finalize_custom_response(request, response, "builtin-put-denied")
    response = PlainTextResponse("not found", status_code=404)
    response.set_cookie("bh_client_id", runtime.get_client_id(request), httponly=False)
    return response


@app.get("/webdav/", response_class=HTMLResponse)
@app.get("/webdav/{item:path}", response_class=HTMLResponse)
async def webdav_index(request: Request, item: str = "") -> Response:
    client_id = runtime.get_client_id(request)
    dav = dict(runtime.state.recall(client_id, "webdav_items", {}) or {"public.txt": "hello from dav"})
    if item and item in dav:
        return PlainTextResponse(dav[item], status_code=200)
    listing = "".join(f'<li><a href="/webdav/{html.escape(name)}">{html.escape(name)}</a></li>' for name in sorted(dav.keys()))
    body = f'<section class="panel"><h2>Index of /webdav/</h2>{_truth_hint_script("builtin-webdav-options")}<ul>{listing}</ul></section>'
    return HTMLResponse(_page_shell("WebDAV index", "<p>Writable WebDAV surface with classic methods.</p>", body))


@app.api_route("/webdav/", methods=["OPTIONS", "PROPFIND", "PUT", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"])
@app.api_route("/webdav/{item:path}", methods=["OPTIONS", "PROPFIND", "PUT", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"])
async def webdav_vuln(request: Request, item: str = ""):
    client_id = runtime.get_client_id(request)
    dav = dict(runtime.state.recall(client_id, "webdav_items", {}) or {"public.txt": "hello from dav"})
    method = request.method.upper()
    target = item or ""
    if method == "OPTIONS":
        response = Response(status_code=204, headers={"Allow": "OPTIONS, PROPFIND, PUT, MKCOL, COPY, MOVE, LOCK, UNLOCK", "DAV": "1,2"})
        return await _finalize_custom_response(request, response, "builtin-webdav-options")
    if method == "PROPFIND":
        items = sorted(dav.keys())
        xml_items = "".join(f"<response><href>/webdav/{html.escape(name)}</href></response>" for name in items)
        response = Response(f'<?xml version="1.0"?><multistatus xmlns="DAV:"><response><href>/webdav/</href></response>{xml_items}</multistatus>', status_code=207, media_type="application/xml")
        return await _finalize_custom_response(request, response, "builtin-webdav-propfind")
    if method == "PUT":
        body = (await request.body()).decode("utf-8", errors="replace")
        dav[target or "uploaded.txt"] = body
        runtime.state.remember(client_id, "webdav_items", dav)
        response = JSONResponse({"stored": True, "href": f"/webdav/{target or 'uploaded.txt'}"}, status_code=201)
        return await _finalize_custom_response(request, response, "builtin-webdav-options")
    if method == "MKCOL":
        response = JSONResponse({"created": True, "collection": target or "/webdav/newdir/"}, status_code=201)
        return await _finalize_custom_response(request, response, "builtin-webdav-options")
    if method in {"COPY", "MOVE", "LOCK", "UNLOCK"}:
        response = JSONResponse({"method": method, "ok": True, "href": f"/webdav/{target}"}, status_code=200)
        return await _finalize_custom_response(request, response, "builtin-webdav-options")
    response = JSONResponse({"error": "unsupported"}, status_code=405)
    return await _finalize_custom_response(request, response, "builtin-webdav-options")


@app.get("/webdav-safe/", response_class=HTMLResponse)
@app.get("/webdav-safe/{item:path}", response_class=HTMLResponse)
async def webdav_safe_index(request: Request, item: str = "") -> Response:
    body = f'<section class="panel"><h2>Index of /webdav-safe/</h2>{_truth_hint_script("builtin-webdav-safe-options")}<ul><li>readme.txt</li></ul></section>'
    return HTMLResponse(_page_shell("WebDAV safe index", "<p>Read-only WebDAV control.</p>", body))


@app.api_route("/webdav-safe/", methods=["OPTIONS", "PROPFIND", "PUT", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"])
@app.api_route("/webdav-safe/{item:path}", methods=["OPTIONS", "PROPFIND", "PUT", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"])
async def webdav_safe(request: Request, item: str = ""):
    method = request.method.upper()
    if method == "OPTIONS":
        response = Response(status_code=204, headers={"Allow": "OPTIONS, PROPFIND", "DAV": "1"})
        return await _finalize_custom_response(request, response, "builtin-webdav-safe-options")
    if method == "PROPFIND":
        response = Response('<?xml version="1.0"?><multistatus xmlns="DAV:"><response><href>/webdav-safe/</href></response></multistatus>', status_code=207, media_type="application/xml")
        return await _finalize_custom_response(request, response, "builtin-webdav-safe-propfind")
    response = JSONResponse({"blocked_by_policy": True, "method": method}, status_code=405)
    return await _finalize_custom_response(request, response, "builtin-webdav-safe-options")



# -------- client-side, authorization, predictable-token, and OIDC companion packs --------

AUTHZ_PROJECTS = {
    "1001": {"owner": "alice", "name": "Roadmap", "classification": "internal"},
    "1002": {"owner": "bob", "name": "Payroll", "classification": "confidential"},
    "1003": {"owner": "charlie", "name": "Acquisition", "classification": "restricted"},
}
AUTHZ_SHARE_TOKENS = {
    "share-alpha-1002": {"project_id": "1002", "recipient": "bob"},
    "share-opaque-1003": {"project_id": "1003", "recipient": "charlie"},
}
OIDC_DISCOVERY = {
    "issuer": "https://blackhole.local/oidc",
    "authorization_endpoint": "https://blackhole.local/oidc/request-object",
    "token_endpoint": "https://blackhole.local/oidc/token",
    "jwks_uri": "https://blackhole.local/.well-known/jwks.json",
    "userinfo_endpoint": "https://blackhole.local/oidc/userinfo",
    "registration_endpoint": "https://blackhole.local/oidc/register",
    "scopes_supported": ["openid", "profile", "email"],
    "response_types_supported": ["code", "id_token"],
    "grant_types_supported": ["authorization_code", "client_credentials"],
    "request_uri_parameter_supported": True,
    "require_request_uri_registration": False,
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256", "HS256"],
}
OIDC_JWKS = {
    "keys": [
        {
            "kty": "RSA",
            "kid": "bh-demo-1",
            "use": "sig",
            "alg": "RS256",
            "n": "00demo-blackhole-modulus",
            "e": "AQAB",
        }
    ]
}


def _project_record(project_id: str) -> dict | None:
    return AUTHZ_PROJECTS.get(project_id)


def _ids_from_payload(payload: dict) -> list[str]:
    raw = payload.get("ids") or payload.get("project_ids") or payload.get("id") or ""
    if isinstance(raw, list):
        return [str(x) for x in raw]
    if isinstance(raw, str):
        return [part.strip() for part in raw.split(",") if part.strip()]
    return []


def _predictable_reset_token(email: str) -> str:
    local = (email.split("@", 1)[0] or "user").lower()
    return f"rst-{local}-2024"


def _predictable_invite_token(user: str) -> str:
    return f"invite-{user.lower()}-2024"


def _predictable_session_id(user: str) -> str:
    return f"sid-{user.lower()}-20240307"


@app.get('/spa/dom-search', response_class=HTMLResponse)
async def spa_dom_search(request: Request) -> Response:
    body = f'''
    <section class="panel">
      <h2>SPA DOM search</h2>
      {_truth_hint_script('builtin-dom-xss')}
      <p>This page reads <code>?q=</code> or the hash fragment on the client side and writes it into the DOM.</p>
      <form method="GET" action="/spa/dom-search"><input type="text" name="q" value="&lt;img src=x onerror=alert(1)&gt;"><button type="submit">Render</button></form>
      <p><a href="/spa/dom-search?q=%3Cimg%20src=x%20onerror=alert(1)%3E">DOM XSS sample</a> | <a href="/spa/dom-search-safe?q=%3Cimg%20src=x%20onerror=alert(1)%3E">safe control</a></p>
      <div id="results"></div>
      <script>
        const params = new URLSearchParams(window.location.search);
        const value = params.get('q') || decodeURIComponent((window.location.hash || '').replace(/^#/, ''));
        document.getElementById('results').innerHTML = value || '<em>empty</em>';
      </script>
    </section>
    '''
    return await _finalize_custom_response(request, HTMLResponse(_page_shell('SPA DOM search lab', '', body)), 'builtin-dom-xss')


@app.get('/spa/dom-search-safe', response_class=HTMLResponse)
async def spa_dom_search_safe(request: Request) -> Response:
    body = f'''
    <section class="panel">
      <h2>SPA DOM search safe control</h2>
      {_truth_hint_script('builtin-dom-xss-safe')}
      <p>This control route writes the same value using <code>textContent</code>.</p>
      <form method="GET" action="/spa/dom-search-safe"><input type="text" name="q" value="&lt;img src=x onerror=alert(1)&gt;"><button type="submit">Render safely</button></form>
      <div id="results"></div>
      <script>
        const params = new URLSearchParams(window.location.search);
        const value = params.get('q') || decodeURIComponent((window.location.hash || '').replace(/^#/, ''));
        document.getElementById('results').textContent = value || 'empty';
      </script>
    </section>
    '''
    return await _finalize_custom_response(request, HTMLResponse(_page_shell('SPA DOM search safe', '', body)), 'builtin-dom-xss-safe')


@app.get('/spa/html-preview', response_class=HTMLResponse)
async def spa_html_preview(request: Request) -> Response:
    body = f'''
    <section class="panel">
      <h2>Client-side HTML preview</h2>
      {_truth_hint_script('builtin-html-injection')}
      <p>The preview widget writes attacker-controlled HTML into a live preview pane.</p>
      <form method="GET" action="/spa/html-preview"><input type="text" name="html" value="&lt;svg onload=alert(1)&gt;"><button type="submit">Preview</button></form>
      <div id="preview"></div>
      <script>
        const params = new URLSearchParams(window.location.search);
        const value = params.get('html') || '&lt;em&gt;empty&lt;/em&gt;';
        document.getElementById('preview').innerHTML = value;
      </script>
    </section>
    '''
    return await _finalize_custom_response(request, HTMLResponse(_page_shell('HTML injection preview', '', body)), 'builtin-html-injection')


@app.get('/spa/html-preview-safe', response_class=HTMLResponse)
async def spa_html_preview_safe(request: Request) -> Response:
    body = f'''
    <section class="panel">
      <h2>Client-side HTML preview safe control</h2>
      {_truth_hint_script('builtin-html-injection-safe')}
      <form method="GET" action="/spa/html-preview-safe"><input type="text" name="html" value="&lt;svg onload=alert(1)&gt;"><button type="submit">Preview safely</button></form>
      <div id="preview"></div>
      <script>
        const params = new URLSearchParams(window.location.search);
        const value = params.get('html') || 'empty';
        document.getElementById('preview').textContent = value;
      </script>
    </section>
    '''
    return await _finalize_custom_response(request, HTMLResponse(_page_shell('HTML injection safe', '', body)), 'builtin-html-injection-safe')


@app.get('/authz/lab', response_class=HTMLResponse)
async def authz_lab(request: Request) -> Response:
    body = f'''
    <section class="panel">
      <h2>Authorization and object-state lab</h2>
      {_truth_hint_script('builtin-authz-project-read')}
      <ul>
        <li><a href="/api/projects?id=1002&viewer=alice">Sequential IDOR read</a> | <a href="/api/projects-safe?id=1002&viewer=alice">safe control</a></li>
        <li><a href="/api/shares?token=share-alpha-1002&viewer=alice">Opaque token share access</a> | <a href="/api/shares-safe?token=share-alpha-1002&viewer=alice">safe control</a></li>
        <li><a href="/api/access-request/result?request_id=ar-0001&viewer=alice">Second-order access result</a></li>
      </ul>
      <form method="POST" action="/api/bulk-export">
        <input type="hidden" name="viewer" value="alice">
        <input type="text" name="ids" value="1001,1002">
        <button type="submit">Bulk export (vulnerable)</button>
      </form>
      <form method="POST" action="/api/bulk-export-safe">
        <input type="hidden" name="viewer" value="alice">
        <input type="text" name="ids" value="1001,1002">
        <button type="submit">Bulk export (safe)</button>
      </form>
    </section>
    '''
    return await _finalize_custom_response(request, HTMLResponse(_page_shell('Authorization / object-state lab', '', body)), 'builtin-authz-project-read')


@app.get('/api/projects')
async def authz_project_read(request: Request, id: str = '1001', viewer: str = 'alice'):
    project = _project_record(id)
    if not project:
        return await _finalize_custom_response(request, JSONResponse({'not_found': True, 'id': id}, status_code=404), 'builtin-authz-project-read')
    data = {'project_id': id, 'viewer': viewer, **project, 'authorized': viewer == project['owner'], 'ownership_enforced': False}
    return await _finalize_custom_response(request, JSONResponse(data), 'builtin-authz-project-read')


@app.get('/api/projects-safe')
async def authz_project_read_safe(request: Request, id: str = '1001', viewer: str = 'alice'):
    project = _project_record(id)
    if not project:
        return await _finalize_custom_response(request, JSONResponse({'not_found': True, 'id': id}, status_code=404), 'builtin-authz-project-read-safe')
    if viewer != project['owner']:
        return await _finalize_custom_response(request, JSONResponse({'access_denied': True, 'viewer': viewer, 'owner': project['owner'], 'ownership_enforced': True}, status_code=403), 'builtin-authz-project-read-safe')
    return await _finalize_custom_response(request, JSONResponse({'project_id': id, 'viewer': viewer, **project, 'authorized': True, 'ownership_enforced': True}), 'builtin-authz-project-read-safe')


@app.get('/api/shares')
async def authz_share_access(request: Request, token: str = 'share-alpha-1002', viewer: str = 'alice'):
    share = AUTHZ_SHARE_TOKENS.get(token)
    if not share:
        return await _finalize_custom_response(request, JSONResponse({'invalid_share': True, 'token': token}, status_code=404), 'builtin-authz-share-token')
    project = _project_record(share['project_id'])
    return await _finalize_custom_response(request, JSONResponse({'share_token': token, 'viewer': viewer, 'recipient': share['recipient'], 'project': project, 'recipient_enforced': False}), 'builtin-authz-share-token')


@app.get('/api/shares-safe')
async def authz_share_access_safe(request: Request, token: str = 'share-alpha-1002', viewer: str = 'alice'):
    share = AUTHZ_SHARE_TOKENS.get(token)
    if not share:
        return await _finalize_custom_response(request, JSONResponse({'invalid_share': True, 'token': token}, status_code=404), 'builtin-authz-share-token-safe')
    if viewer != share['recipient']:
        return await _finalize_custom_response(request, JSONResponse({'access_denied': True, 'viewer': viewer, 'recipient': share['recipient'], 'recipient_enforced': True}, status_code=403), 'builtin-authz-share-token-safe')
    project = _project_record(share['project_id'])
    return await _finalize_custom_response(request, JSONResponse({'share_token': token, 'viewer': viewer, 'project': project, 'recipient_enforced': True}), 'builtin-authz-share-token-safe')


@app.post('/api/bulk-export')
async def authz_bulk_export(request: Request):
    payload = await _request_data(request)
    viewer = str(payload.get('viewer') or 'alice')
    ids = _ids_from_payload(payload)
    exported = []
    for pid in ids:
        project = _project_record(pid)
        if project:
            exported.append({'project_id': pid, 'owner': project['owner'], 'name': project['name']})
    return await _finalize_custom_response(request, JSONResponse({'viewer': viewer, 'requested_ids': ids, 'exported': exported, 'ownership_enforced': False}), 'builtin-authz-bulk-export')


@app.post('/api/bulk-export-safe')
async def authz_bulk_export_safe(request: Request):
    payload = await _request_data(request)
    viewer = str(payload.get('viewer') or 'alice')
    ids = _ids_from_payload(payload)
    exported = []
    denied = []
    for pid in ids:
        project = _project_record(pid)
        if not project:
            continue
        if project['owner'] == viewer:
            exported.append({'project_id': pid, 'owner': project['owner'], 'name': project['name']})
        else:
            denied.append(pid)
    status = 403 if denied else 200
    return await _finalize_custom_response(request, JSONResponse({'viewer': viewer, 'requested_ids': ids, 'exported': exported, 'denied_ids': denied, 'ownership_enforced': True}, status_code=status), 'builtin-authz-bulk-export-safe')


@app.post('/api/access-request')
async def authz_access_request(request: Request):
    payload = await _request_data(request)
    client_id = runtime.get_client_id(request)
    viewer = str(payload.get('viewer') or 'alice')
    project_id = str(payload.get('project_id') or '1002')
    target_user = str(payload.get('target_user') or 'bob')
    counter = int(runtime.state.recall(client_id, 'authz_request_counter', 0) or 0) + 1
    runtime.state.remember(client_id, 'authz_request_counter', counter)
    request_id = f'ar-{counter:04d}'
    requests = dict(runtime.state.recall(client_id, 'authz_requests', {}) or {})
    requests[request_id] = {'requester': viewer, 'project_id': project_id, 'target_user': target_user, 'status': 'pending', 'approved_by': None}
    runtime.state.remember(client_id, 'authz_requests', requests)
    return await _finalize_custom_response(request, JSONResponse({'request_id': request_id, 'requester': viewer, 'project_id': project_id, 'target_user': target_user, 'status': 'pending'}, status_code=201), 'builtin-authz-access-request')


@app.get('/api/access-request/approve')
async def authz_access_request_approve(request: Request, request_id: str = 'ar-0001', viewer: str = 'bob'):
    client_id = runtime.get_client_id(request)
    requests = dict(runtime.state.recall(client_id, 'authz_requests', {}) or {})
    item = requests.get(request_id)
    if not item:
        return await _finalize_custom_response(request, JSONResponse({'request_not_found': True, 'request_id': request_id}, status_code=404), 'builtin-authz-access-request-approve')
    item['status'] = 'approved'
    item['approved_by'] = viewer
    requests[request_id] = item
    runtime.state.remember(client_id, 'authz_requests', requests)
    return await _finalize_custom_response(request, JSONResponse({'request_id': request_id, 'approved_by': viewer, 'status': item['status'], 'target_user': item['target_user'], 'approval_authorized': viewer == item['target_user'], 'approval_enforced': False}), 'builtin-authz-access-request-approve')


@app.get('/api/access-request/approve-safe')
async def authz_access_request_approve_safe(request: Request, request_id: str = 'ar-0001', viewer: str = 'bob'):
    client_id = runtime.get_client_id(request)
    requests = dict(runtime.state.recall(client_id, 'authz_requests', {}) or {})
    item = requests.get(request_id)
    if not item:
        return await _finalize_custom_response(request, JSONResponse({'request_not_found': True, 'request_id': request_id}, status_code=404), 'builtin-authz-access-request-approve-safe')
    if viewer != item['target_user']:
        return await _finalize_custom_response(request, JSONResponse({'access_denied': True, 'request_id': request_id, 'viewer': viewer, 'required_approver': item['target_user'], 'approval_enforced': True}, status_code=403), 'builtin-authz-access-request-approve-safe')
    item['status'] = 'approved'
    item['approved_by'] = viewer
    requests[request_id] = item
    runtime.state.remember(client_id, 'authz_requests', requests)
    return await _finalize_custom_response(request, JSONResponse({'request_id': request_id, 'approved_by': viewer, 'status': item['status'], 'approval_enforced': True}), 'builtin-authz-access-request-approve-safe')


@app.get('/api/access-request/result')
async def authz_access_request_result(request: Request, request_id: str = 'ar-0001', viewer: str = 'alice'):
    client_id = runtime.get_client_id(request)
    requests = dict(runtime.state.recall(client_id, 'authz_requests', {}) or {})
    item = requests.get(request_id)
    if not item:
        return await _finalize_custom_response(request, JSONResponse({'request_not_found': True, 'request_id': request_id}, status_code=404), 'builtin-authz-access-request-approve')
    project = _project_record(item['project_id'])
    body = {'request_id': request_id, 'viewer': viewer, 'requester': item['requester'], 'status': item['status'], 'approved_by': item['approved_by'], 'project': project if item['status'] == 'approved' else None, 'second_order_effect': item['status'] == 'approved'}
    return await _finalize_custom_response(request, JSONResponse(body), 'builtin-authz-access-request-approve')


@app.get('/tokens/lab', response_class=HTMLResponse)
async def token_lab(request: Request) -> Response:
    body = f'''
    <section class="panel">
      <h2>Predictable token and brute-force lab</h2>
      {_truth_hint_script('builtin-predictable-reset-confirm')}
      <ul>
        <li><a href="/reset/confirm?email=alice%40example.org&token=rst-alice-2024">Predictable reset token</a> | <a href="/reset/confirm-safe?email=alice%40example.org&token=rst-alice-2024">safe control</a></li>
        <li><a href="/invite/accept?user=bob&token=invite-bob-2024">Predictable invite token</a> | <a href="/invite/accept-safe?user=bob&token=invite-bob-2024">safe control</a></li>
        <li><a href="/session/profile?user=alice&sid=sid-alice-20240307">Predictable session identifier</a> | <a href="/session/profile-safe?user=alice&sid=sid-alice-20240307">safe control</a></li>
      </ul>
      <form method="POST" action="/otp/verify"><input type="hidden" name="user" value="alice"><input type="text" name="code" value="111111"><button type="submit">OTP verify</button></form>
      <form method="POST" action="/otp/verify-safe"><input type="hidden" name="user" value="alice"><input type="text" name="code" value="111111"><button type="submit">OTP verify safe</button></form>
    </section>
    '''
    return await _finalize_custom_response(request, HTMLResponse(_page_shell('Predictable token / brute-force lab', '', body)), 'builtin-predictable-reset-confirm')


@app.post('/reset/request')
async def reset_request(request: Request):
    payload = await _request_data(request)
    email = str(payload.get('email') or 'alice@example.org')
    token = _predictable_reset_token(email)
    client_id = runtime.get_client_id(request)
    _append_history(client_id, 'reset_history', {'email': email, 'token': token, 'predictable': True})
    return await _finalize_custom_response(request, JSONResponse({'ok': True, 'email': email, 'delivery': 'generic', 'predictable_token_shape': token}), 'builtin-predictable-reset-request')


@app.post('/reset/request-safe')
async def reset_request_safe(request: Request):
    payload = await _request_data(request)
    email = str(payload.get('email') or 'alice@example.org')
    client_id = runtime.get_client_id(request)
    token = f"rst-{secrets.token_hex(8)}"
    issued = dict(runtime.state.recall(client_id, 'reset_tokens_safe', {}) or {})
    issued[email] = token
    runtime.state.remember(client_id, 'reset_tokens_safe', issued)
    return await _finalize_custom_response(request, JSONResponse({'ok': True, 'email': email, 'delivery': 'generic'}), 'builtin-predictable-reset-confirm-safe')


@app.get('/reset/confirm')
async def reset_confirm(request: Request, email: str = 'alice@example.org', token: str = 'rst-alice-2024', new_password: str = 'P@ssw0rd!'):
    expected = _predictable_reset_token(email)
    if token == expected:
        return await _finalize_custom_response(request, JSONResponse({'password_reset': True, 'email': email, 'token_accepted': token, 'predictable': True, 'new_password_applied': True}), 'builtin-predictable-reset-confirm')
    return await _finalize_custom_response(request, JSONResponse({'password_reset': False, 'invalid_token': True, 'expected_shape': expected}, status_code=400), 'builtin-predictable-reset-confirm')


@app.get('/reset/confirm-safe')
async def reset_confirm_safe(request: Request, email: str = 'alice@example.org', token: str = 'rst-alice-2024', new_password: str = 'P@ssw0rd!'):
    client_id = runtime.get_client_id(request)
    issued = dict(runtime.state.recall(client_id, 'reset_tokens_safe', {}) or {})
    expected = issued.get(email)
    if expected and token == expected:
        return await _finalize_custom_response(request, JSONResponse({'password_reset': True, 'email': email, 'token_accepted': token, 'predictable': False}), 'builtin-predictable-reset-confirm-safe')
    return await _finalize_custom_response(request, JSONResponse({'password_reset': False, 'invalid_token': True, 'predictable_formula_rejected': True}, status_code=403), 'builtin-predictable-reset-confirm-safe')


@app.get('/invite/accept')
async def invite_accept(request: Request, user: str = 'bob', token: str = 'invite-bob-2024'):
    expected = _predictable_invite_token(user)
    ok = token == expected
    status = 200 if ok else 400
    return await _finalize_custom_response(request, JSONResponse({'invite_accepted': ok, 'user': user, 'token': token, 'predictable': True}, status_code=status), 'builtin-predictable-invite-accept')


@app.get('/invite/accept-safe')
async def invite_accept_safe(request: Request, user: str = 'bob', token: str = 'invite-bob-2024'):
    client_id = runtime.get_client_id(request)
    invites = dict(runtime.state.recall(client_id, 'safe_invites', {}) or {})
    if invites.get(user) == token:
        return await _finalize_custom_response(request, JSONResponse({'invite_accepted': True, 'user': user, 'predictable': False}), 'builtin-predictable-invite-accept-safe')
    return await _finalize_custom_response(request, JSONResponse({'invite_accepted': False, 'predictable_formula_rejected': True}, status_code=403), 'builtin-predictable-invite-accept-safe')


@app.get('/session/start')
async def session_start(request: Request, user: str = 'alice'):
    sid = _predictable_session_id(user)
    client_id = runtime.get_client_id(request)
    sessions = dict(runtime.state.recall(client_id, 'vuln_sessions', {}) or {})
    sessions[user] = sid
    runtime.state.remember(client_id, 'vuln_sessions', sessions)
    return await _finalize_custom_response(request, JSONResponse({'user': user, 'session_id': sid, 'predictable': True}), 'builtin-predictable-session')


@app.get('/session/profile')
async def session_profile(request: Request, user: str = 'alice', sid: str = 'sid-alice-20240307'):
    expected = _predictable_session_id(user)
    if sid == expected:
        return await _finalize_custom_response(request, JSONResponse({'user': user, 'session_valid': True, 'profile': {'role': 'user', 'email': f'{user}@example.org'}, 'predictable': True}), 'builtin-predictable-session')
    return await _finalize_custom_response(request, JSONResponse({'user': user, 'session_valid': False, 'invalid_sid': True}, status_code=403), 'builtin-predictable-session')


@app.get('/session/start-safe')
async def session_start_safe(request: Request, user: str = 'alice'):
    client_id = runtime.get_client_id(request)
    sid = f'sid-{secrets.token_hex(12)}'
    sessions = dict(runtime.state.recall(client_id, 'safe_sessions', {}) or {})
    sessions[user] = sid
    runtime.state.remember(client_id, 'safe_sessions', sessions)
    return await _finalize_custom_response(request, JSONResponse({'user': user, 'session_id': sid, 'predictable': False}), 'builtin-predictable-session-safe')


@app.get('/session/profile-safe')
async def session_profile_safe(request: Request, user: str = 'alice', sid: str = 'sid-alice-20240307'):
    client_id = runtime.get_client_id(request)
    sessions = dict(runtime.state.recall(client_id, 'safe_sessions', {}) or {})
    if sessions.get(user) == sid:
        return await _finalize_custom_response(request, JSONResponse({'user': user, 'session_valid': True, 'predictable': False}), 'builtin-predictable-session-safe')
    return await _finalize_custom_response(request, JSONResponse({'user': user, 'session_valid': False, 'predictable_formula_rejected': True}, status_code=403), 'builtin-predictable-session-safe')


@app.post('/otp/verify')
async def otp_verify(request: Request):
    payload = await _request_data(request)
    user = str(payload.get('user') or 'alice')
    code = str(payload.get('code') or '')
    status = 200 if code == '111111' else 401
    return await _finalize_custom_response(request, JSONResponse({'user': user, 'otp_valid': code == '111111', 'lockout_enforced': False, 'attempt_budget_enforced': False}, status_code=status), 'builtin-otp-verify')


@app.post('/otp/verify-safe')
async def otp_verify_safe(request: Request):
    payload = await _request_data(request)
    user = str(payload.get('user') or 'alice')
    code = str(payload.get('code') or '')
    client_id = runtime.get_client_id(request)
    attempts = dict(runtime.state.recall(client_id, 'otp_safe_attempts', {}) or {})
    attempts[user] = int(attempts.get(user, 0)) + 1
    runtime.state.remember(client_id, 'otp_safe_attempts', attempts)
    if attempts[user] > 5:
        return await _finalize_custom_response(request, JSONResponse({'user': user, 'locked': True, 'lockout_enforced': True}, status_code=423), 'builtin-otp-verify-safe')
    status = 200 if code == '111111' else 401
    return await _finalize_custom_response(request, JSONResponse({'user': user, 'otp_valid': code == '111111', 'attempts': attempts[user], 'lockout_enforced': True}, status_code=status), 'builtin-otp-verify-safe')


@app.post('/otp/resend')
async def otp_resend(request: Request):
    payload = await _request_data(request)
    user = str(payload.get('user') or 'alice')
    client_id = runtime.get_client_id(request)
    counters = dict(runtime.state.recall(client_id, 'otp_resend_vuln', {}) or {})
    counters[user] = int(counters.get(user, 0)) + 1
    runtime.state.remember(client_id, 'otp_resend_vuln', counters)
    return await _finalize_custom_response(request, JSONResponse({'user': user, 'resent': True, 'count': counters[user], 'rate_limit_enforced': False}), 'builtin-otp-resend')


@app.post('/otp/resend-safe')
async def otp_resend_safe(request: Request):
    payload = await _request_data(request)
    user = str(payload.get('user') or 'alice')
    client_id = runtime.get_client_id(request)
    counters = dict(runtime.state.recall(client_id, 'otp_resend_safe', {}) or {})
    counters[user] = int(counters.get(user, 0)) + 1
    runtime.state.remember(client_id, 'otp_resend_safe', counters)
    if counters[user] > 3:
        return await _finalize_custom_response(request, JSONResponse({'user': user, 'resent': False, 'count': counters[user], 'rate_limit_enforced': True}, status_code=429), 'builtin-otp-resend-safe')
    return await _finalize_custom_response(request, JSONResponse({'user': user, 'resent': True, 'count': counters[user], 'rate_limit_enforced': True}), 'builtin-otp-resend-safe')


@app.get('/oidc/discovery-lab', response_class=HTMLResponse)
async def oidc_discovery_lab(request: Request) -> Response:
    body = f'''
    <section class="panel">
      <h2>OIDC discovery and request_uri lab</h2>
      {_truth_hint_script('builtin-oidc-discovery')}
      <ul>
        <li><a href="/.well-known/openid-configuration">OpenID discovery document</a></li>
        <li><a href="/.well-known/jwks.json">JWKS document</a></li>
        <li><a href="/oidc/request-object?client_id=demo-client&request_uri=http://169.254.169.254/latest/meta-data/iam/security-credentials/">request_uri vulnerable flow</a> | <a href="/oidc/request-object-safe?client_id=demo-client&request_uri=http://169.254.169.254/latest/meta-data/iam/security-credentials/">safe control</a></li>
        <li><a href="/oidc/webfinger?resource=acct:alice@blackhole.local">WebFinger enum</a> | <a href="/oidc/webfinger-safe?resource=acct:alice@blackhole.local">safe control</a></li>
      </ul>
    </section>
    '''
    return await _finalize_custom_response(request, HTMLResponse(_page_shell('OIDC discovery / request_uri lab', '', body)), 'builtin-oidc-discovery')


@app.get('/.well-known/openid-configuration')
async def oidc_openid_configuration(request: Request):
    return await _finalize_custom_response(request, JSONResponse(OIDC_DISCOVERY), 'builtin-oidc-discovery')


@app.get('/.well-known/jwks.json')
async def oidc_jwks(request: Request):
    return await _finalize_custom_response(request, JSONResponse(OIDC_JWKS), 'builtin-oidc-jwks')


@app.get('/oidc/request-object')
async def oidc_request_object(request: Request, client_id: str = 'demo-client', request_uri: str | None = None):
    target = request_uri or 'https://attacker.example/request.jwt'
    body = {
        'client_id': client_id,
        'request_uri': target,
        'request_object_fetched': True,
        'request_uri_enforced': False,
        'internal_fetch': _looks_internal_url(target),
        'allowlisted': False,
    }
    return await _finalize_custom_response(request, JSONResponse(body), 'builtin-oidc-request-object')


@app.get('/oidc/request-object-safe')
async def oidc_request_object_safe(request: Request, client_id: str = 'demo-client', request_uri: str | None = None):
    target = request_uri or 'https://attacker.example/request.jwt'
    parsed = urlparse(target)
    is_https = parsed.scheme == 'https'
    allowlisted = parsed.netloc in {'trusted.example', 'login.example'}
    if not target or _looks_internal_url(target) or not is_https or not allowlisted:
        return await _finalize_custom_response(request, JSONResponse({'client_id': client_id, 'request_uri': target, 'request_uri_not_allowed': True, 'registration_required': True, 'allowlisted': allowlisted}, status_code=400), 'builtin-oidc-request-object-safe')
    return await _finalize_custom_response(request, JSONResponse({'client_id': client_id, 'request_uri': target, 'request_object_fetched': True, 'request_uri_enforced': True, 'allowlisted': True}), 'builtin-oidc-request-object-safe')


@app.get('/oidc/webfinger')
async def oidc_webfinger(request: Request, resource: str = 'acct:alice@blackhole.local'):
    known = {'acct:alice@blackhole.local': 'alice', 'acct:bob@blackhole.local': 'bob'}
    if resource in known:
        return await _finalize_custom_response(request, JSONResponse({'subject': resource, 'links': [{'rel': 'http://openid.net/specs/connect/1.0/issuer', 'href': OIDC_DISCOVERY['issuer']}], 'enumeration_possible': True}), 'builtin-oidc-webfinger-enum')
    return await _finalize_custom_response(request, JSONResponse({'subject': resource, 'not_found': True}, status_code=404), 'builtin-oidc-webfinger-enum')


@app.get('/oidc/webfinger-safe')
async def oidc_webfinger_safe(request: Request, resource: str = 'acct:alice@blackhole.local'):
    return await _finalize_custom_response(request, JSONResponse({'resource_checked': True, 'generic_not_found': True}, status_code=404), 'builtin-oidc-webfinger-safe')

@app.get("/__blackhole/truth-manifest.json")
def truth_manifest() -> list[dict]:
    return runtime.list_truth()
@app.get("/__blackhole/health")
def health() -> dict:
    return runtime.admin_status()


@app.get("/__blackhole/profiles")
def profiles() -> list[dict]:
    return runtime.list_profiles()


@app.get("/__blackhole/truth")
def truth() -> list[dict]:
    return runtime.list_truth()


@app.get("/__blackhole/logs")
def logs() -> list[dict]:
    return runtime.request_log_dump()


@app.get("/__blackhole/state")
def state(request: Request) -> dict:
    client_id = runtime.get_client_id(request)
    return {
        "client_id": client_id,
        "scenario_state": runtime.state.snapshot(client_id),
        "memory": runtime.state.memory_snapshot(client_id),
    }


@app.post("/__blackhole/reset")
def reset() -> dict:
    runtime.reset()
    return {"ok": True}


@app.post("/__blackhole/load")
def load_pack_endpoint(payload: dict = Body(...)) -> dict:
    global runtime
    pack_path = payload.get("pack_path")
    if not pack_path:
        raise HTTPException(status_code=400, detail="pack_path is required")
    pack = load_pack(pack_path)
    runtime = BlackholeRuntime(pack)
    return {"ok": True, "pack": runtime.pack.name, "profiles_total": len(runtime.profiles)}


@app.post("/__blackhole/score")
def score(payload: ScoreRequest) -> dict:
    return runtime.score(payload).model_dump(mode="json")


async def _has_direct_match(request: Request) -> bool:
    client_id = runtime.get_client_id(request)
    for profile in runtime.profiles:
        if not runtime._scenario_allowed(client_id, profile):
            continue
        if await match_request(request, profile):
            return True
    return False



def _path_candidates(path: str) -> list[ReplayProfile]:
    return [p for p in runtime.profiles if p.matcher.path == path]



def _render_path_discovery(path: str, candidates: list[ReplayProfile]) -> str:
    method_counts = Counter(_method_badge(p) for p in candidates)
    items = []
    for profile in sorted(candidates, key=lambda p: (p.matcher.method, p.title.lower(), p.id)):
        body = _render_form_for_profile(profile)
        items.append(
            f'<section class="panel"><h3>{html.escape(profile.title)}</h3>'
            f'<p>{html.escape(profile.truth.vuln_class)} · <span class="method">{html.escape(_method_badge(profile))}</span></p>'
            f'<p><a href="{html.escape(_discovery_path(profile))}">Profile discovery page</a> · <a href="/__blackhole/profile/{html.escape(profile.id)}">profile json</a></p>'
            f'<pre>{html.escape(_sample_curl_for_profile(profile))}</pre>{body}</section>'
        )
    intro = (
        f"<p>No direct profile matched this <code>GET {html.escape(path)}</code> request, but the path is still part of the benchmark pack.</p>"
        "<p>That means the endpoint is likely POST-only or needs extra headers or body content. The sections below expose crawler-friendly forms and exact sample requests.</p>"
    )
    return _page_shell(f"Endpoint discovery: {path}", intro, "".join(items), method_counts)


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE", "PROPFIND", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"])
async def replay(full_path: str, request: Request):
    if request.method == "GET":
        direct_match = await _has_direct_match(request)
        if not direct_match:
            candidates = _path_candidates(request.url.path)
            if candidates:
                response = HTMLResponse(_render_path_discovery(request.url.path, candidates), status_code=200)
                response.headers.setdefault("X-Blackhole-Profile", "discovery")
                response.headers.setdefault("X-Blackhole-Case", ",".join(p.case_id for p in candidates[:10]))
                return response

    profile, response, _client_id = await runtime.resolve(request)
    if profile:
        response.headers.setdefault("X-Blackhole-Profile", profile.id)
        response.headers.setdefault("X-Blackhole-Case", profile.case_id)
    else:
        response.headers.setdefault("X-Blackhole-Profile", "none")
    return response
