from pathlib import Path

from starlette.testclient import TestClient

from blackhole.app.main import app
from blackhole.app.runtime import BlackholeRuntime


def test_reflected_xss_profile_matches():
    client = TestClient(app)
    response = client.get("/search", params={"q": "<script>alert(1)</script>"})
    assert response.status_code == 200
    assert "<script>alert(1)</script>" in response.text
    assert response.headers["X-Blackhole-Profile"] == "builtin-reflected-xss"


def test_open_redirect_profile_matches():
    client = TestClient(app)
    response = client.get("/redirect", params={"next": "https://evil.example"}, follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == "https://evil.example"


def test_compiled_profile_matches_unique_case_path():
    client = TestClient(app)
    response = client.get("/cases/juice-accesslogdisclosurechallenge/ftp/")
    assert response.status_code == 200
    assert response.headers["X-Blackhole-Profile"] == "compiled-juice-accesslogdisclosurechallenge"


def test_stateful_comment_storage_roundtrip():
    client = TestClient(app)
    payload = {"comment": "<img src=x onerror=alert(1)>"}
    post_response = client.post("/api/comments", json=payload)
    assert post_response.status_code == 201
    get_response = client.get("/comments")
    assert payload["comment"] in get_response.text


def test_score_endpoint_returns_summary():
    client = TestClient(app)
    score_payload = {
        "findings": [
            {"vuln_class": "xss.reflected", "path": "/search"},
            {"vuln_class": "redirect.open", "path": "/redirect"},
        ]
    }
    response = client.post("/__blackhole/score", json=score_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["summary"]["matched_total"] >= 2


def test_root_index_lists_compiled_cases():
    client = TestClient(app)
    response = client.get('/')
    assert response.status_code == 200
    assert 'Blackhole Mock Server' in response.text
    assert 'combined-pack' in response.text
    assert '/cases/juice-accesslogdisclosurechallenge/ftp/' in response.text
    assert '/__blackhole/profile/compiled-juice-accesslogdisclosurechallenge' in response.text


def test_health_shows_enriched_profile_count():
    client = TestClient(app)
    response = client.get('/__blackhole/health')
    assert response.status_code == 200
    data = response.json()
    assert data['profiles_total'] >= 150


def test_root_uses_real_family_links_and_no_loopback_curl_noise():
    client = TestClient(app)
    response = client.get('/')
    assert response.status_code == 200
    assert '/families/xss' in response.text
    assert '127.0.0.1' not in response.text
    assert '/sitemap.xml' in response.text


def test_post_only_path_returns_discovery_page_on_get():
    client = TestClient(app)
    response = client.get('/cases/portswigger-lab-accidental-exposure-of-private-graphql-fields/graphql/v1')
    assert response.status_code == 200
    assert 'Endpoint discovery' in response.text
    assert 'POST endpoint discovery' in response.text
    assert 'X-Blackhole-Profile' in response.headers
    assert response.headers['X-Blackhole-Profile'] == 'discovery'


def test_sitemap_lists_family_and_entry_urls():
    client = TestClient(app)
    response = client.get('/sitemap.xml')
    assert response.status_code == 200
    assert '/families/xss' in response.text
    assert '/__blackhole/entry/' in response.text



def test_webhook_second_order_vulnerable_and_safe_control():
    client = TestClient(app)
    reg = client.post('/api/webhooks/register', json={'target_url': 'http://169.254.169.254/latest/meta-data/', 'event': 'build.complete'})
    assert reg.status_code == 201
    trig = client.get('/api/webhooks/trigger', params={'event': 'build.complete'})
    assert trig.status_code == 200
    assert trig.json()['internal_fetch'] is True

    reg_safe = client.post('/api/webhooks/register-safe', json={'target_url': 'http://169.254.169.254/latest/meta-data/', 'event': 'build.complete'})
    assert reg_safe.status_code == 201
    trig_safe = client.get('/api/webhooks/trigger-safe', params={'event': 'build.complete'})
    assert trig_safe.status_code == 403
    assert trig_safe.json()['blocked_by_policy'] is True


def test_import_second_order_vulnerable_and_safe_control():
    client = TestClient(app)
    reg = client.post('/api/imports/configure', json={'source_url': 'file:///etc/passwd', 'job': 'contacts-sync'})
    assert reg.status_code == 201
    run = client.get('/api/imports/run', params={'job': 'contacts-sync'})
    assert run.status_code == 200
    assert run.json()['local_file_read'] is True

    reg_safe = client.post('/api/imports/configure-safe', json={'source_url': 'file:///etc/passwd', 'job': 'contacts-sync'})
    assert reg_safe.status_code == 201
    run_safe = client.get('/api/imports/run-safe', params={'job': 'contacts-sync'})
    assert run_safe.status_code == 403
    assert run_safe.json()['blocked_by_policy'] is True


def test_oauth_redirect_uri_vulnerable_and_safe_control():
    client = TestClient(app)
    reg = client.post('/oauth/register-client', json={'client_id': 'demo-client', 'redirect_uri': 'https://trusted.example/callback'})
    assert reg.status_code == 201

    vuln = client.get('/oauth/authorize', params={'client_id': 'demo-client', 'redirect_uri': 'https://attacker.example/callback', 'state': 'xyz'}, follow_redirects=False)
    assert vuln.status_code == 302
    assert vuln.headers['location'].startswith('https://attacker.example/callback')

    safe = client.get('/oauth/authorize-safe', params={'client_id': 'demo-client', 'redirect_uri': 'https://attacker.example/callback', 'state': 'xyz'})
    assert safe.status_code == 400
    assert safe.json()['exact_match_required'] is True


def test_truth_manifest_exposes_new_second_order_profiles():
    client = TestClient(app)
    response = client.get('/__blackhole/truth-manifest.json')
    assert response.status_code == 200
    data = response.json()
    ids = {item['profile_id'] for item in data}
    assert 'builtin-webhook-trigger' in ids
    assert 'builtin-oauth-authorize' in ids


def test_basic_auth_challenge_present():
    client = TestClient(app)
    response = client.get('/auth/basic')
    assert response.status_code == 401
    assert response.headers['www-authenticate'].startswith('Basic ')


def test_login_safe_locks_after_repeated_failures_but_weak_does_not():
    client = TestClient(app)
    for _ in range(5):
        weak = client.post('/login', data={'username': 'admin', 'password': 'wrong'})
        assert weak.status_code == 401
    safe_last = None
    for _ in range(5):
        safe_last = client.post('/login-safe', data={'username': 'admin', 'password': 'wrong'})
    assert safe_last is not None
    assert safe_last.status_code == 423


def test_put_writable_and_safe_control():
    client = TestClient(app)
    put_response = client.put('/uploads/poc.txt', content='owned')
    assert put_response.status_code == 201
    get_response = client.get('/uploads/poc.txt')
    assert get_response.status_code == 200
    assert get_response.text == 'owned'
    safe_response = client.put('/uploads-safe/poc.txt', content='owned')
    assert safe_response.status_code == 403


def test_options_and_trace_baseline_routes():
    client = TestClient(app)
    options_response = client.options('/api/methods')
    assert options_response.status_code == 204
    assert 'TRACE' in options_response.headers['allow']
    trace_response = client.request('TRACE', '/trace', headers={'X-Test': '1'})
    assert trace_response.status_code == 200
    assert 'TRACE /trace HTTP/1.1' in trace_response.text


def test_webdav_and_legacy_policy_files_exist():
    client = TestClient(app)
    options_response = client.request('OPTIONS', '/webdav/')
    assert options_response.status_code == 204
    assert options_response.headers['dav'] == '1,2'
    propfind_response = client.request('PROPFIND', '/webdav/')
    assert propfind_response.status_code == 207
    assert 'multistatus' in propfind_response.text
    crossdomain = client.get('/crossdomain.xml')
    assert crossdomain.status_code == 200
    assert '<cross-domain-policy>' in crossdomain.text


def test_dom_xss_and_html_injection_controls_exist():
    client = TestClient(app)
    dom = client.get('/spa/dom-search', params={'q': '<img src=x onerror=alert(1)>'})
    assert dom.status_code == 200
    assert 'innerHTML' in dom.text
    dom_safe = client.get('/spa/dom-search-safe', params={'q': '<img src=x onerror=alert(1)>'})
    assert dom_safe.status_code == 200
    assert 'textContent' in dom_safe.text
    html_preview = client.get('/spa/html-preview', params={'html': '<svg onload=alert(1)>'})
    assert html_preview.status_code == 200
    assert 'preview' in html_preview.text


def test_authz_project_and_bulk_controls():
    client = TestClient(app)
    vuln = client.get('/api/projects', params={'id': '1002', 'viewer': 'alice'})
    assert vuln.status_code == 200
    assert vuln.json()['owner'] == 'bob'
    safe = client.get('/api/projects-safe', params={'id': '1002', 'viewer': 'alice'})
    assert safe.status_code == 403
    bulk_vuln = client.post('/api/bulk-export', data={'viewer': 'alice', 'ids': '1001,1002'})
    assert bulk_vuln.status_code == 200
    assert len(bulk_vuln.json()['exported']) == 2
    bulk_safe = client.post('/api/bulk-export-safe', data={'viewer': 'alice', 'ids': '1001,1002'})
    assert bulk_safe.status_code == 403
    assert '1002' in bulk_safe.json()['denied_ids']


def test_predictable_token_and_session_controls():
    client = TestClient(app)
    reset = client.get('/reset/confirm', params={'email': 'alice@example.org', 'token': 'rst-alice-2024'})
    assert reset.status_code == 200
    reset_safe = client.get('/reset/confirm-safe', params={'email': 'alice@example.org', 'token': 'rst-alice-2024'})
    assert reset_safe.status_code == 403
    session = client.get('/session/profile', params={'user': 'alice', 'sid': 'sid-alice-20240307'})
    assert session.status_code == 200
    session_safe = client.get('/session/profile-safe', params={'user': 'alice', 'sid': 'sid-alice-20240307'})
    assert session_safe.status_code == 403


def test_otp_and_request_uri_controls():
    client = TestClient(app)
    for _ in range(6):
        last = client.post('/otp/verify-safe', data={'user': 'alice', 'code': '000000'})
    assert last.status_code == 423
    oidc = client.get('/.well-known/openid-configuration')
    assert oidc.status_code == 200
    assert oidc.json()['request_uri_parameter_supported'] is True
    req_obj = client.get('/oidc/request-object', params={'client_id': 'demo-client', 'request_uri': 'http://169.254.169.254/latest/meta-data/'})
    assert req_obj.status_code == 200
    assert req_obj.json()['internal_fetch'] is True
    req_obj_safe = client.get('/oidc/request-object-safe', params={'client_id': 'demo-client', 'request_uri': 'http://169.254.169.254/latest/meta-data/'})
    assert req_obj_safe.status_code == 400
