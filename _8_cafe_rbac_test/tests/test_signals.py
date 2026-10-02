"""신규 탐지 신호 — 자기차단 예외, blocked-retry, web-scan, gold-access, admin-auth-fail.

send_gelf 는 conftest.gelf_outbox 가 가로채므로, 실제 UDP 전송 없이
보낸 rule/필드만 payload(JSON 바이트열)에서 확인한다.
"""
import json


def register(client, username, password='PW12345!'):
    return client.post('/api/auth/register', json={'username': username, 'password': password})


def login_token(client, username, password='PW12345!'):
    r = client.post('/api/auth/login', json={'username': username, 'password': password})
    return {'Authorization': f"Bearer {r.get_json()['access_token']}"}


def _rules(outbox, name):
    out = []
    for payload, _addr in outbox:
        msg = json.loads(payload.decode())
        if msg.get('_rule') == name:
            out.append(msg)
    return out


def test_selfblock_exempts_trusted_automation(app_client, api_key, gelf_outbox):
    _app, client = app_client
    ip = '203.0.113.77'
    client.post('/api/admin/block', headers=api_key, json={'ip': ip})

    r = client.get('/api/auth/me', environ_overrides={'REMOTE_ADDR': ip})
    assert r.status_code == 403
    assert len(_rules(gelf_outbox, 'blocked-retry')) == 1

    gelf_outbox.clear()
    r2 = client.get('/api/auth/me', headers=api_key, environ_overrides={'REMOTE_ADDR': ip})
    assert r2.status_code != 403
    assert len(_rules(gelf_outbox, 'blocked-retry')) == 0


def test_web_scan_signal_on_404_excludes_admin_paths(app_client, gelf_outbox):
    _app, client = app_client
    r = client.get('/no/such/path')
    assert r.status_code == 404
    scans = _rules(gelf_outbox, 'web-scan')
    assert len(scans) == 1
    assert scans[0]['_code'] == 404

    gelf_outbox.clear()
    client.get('/api/admin/no-such-route')
    assert len(_rules(gelf_outbox, 'web-scan')) == 0


def test_gold_access_signal(app_client, api_key, gelf_outbox):
    _app, client = app_client
    register(client, 'goldie')
    client.post('/api/admin/grant', headers=api_key, json={'username': 'goldie', 'role': 'gold'})
    token = login_token(client, 'goldie')

    gelf_outbox.clear()
    r = client.get('/api/gold/posts', headers=token)
    assert r.status_code == 200
    signals = _rules(gelf_outbox, 'gold-access')
    assert len(signals) == 1
    assert signals[0]['_username'] == 'goldie'
    assert signals[0]['_role'] == 'gold'


def test_admin_auth_fail_signal_on_bad_security_api_key(app_client, gelf_outbox):
    _app, client = app_client
    r = client.post('/api/security/events',
                     json={'student': 'x', 'src_ip': '1.2.3.4', 'decision': 'deny'})
    assert r.status_code == 401
    fails = _rules(gelf_outbox, 'admin-auth-fail')
    assert len(fails) == 1
    assert fails[0]['_code'] == 401


def test_auto_post_on_deny_creates_board_post(app_client, api_key):
    app, client = app_client
    app.config['AUTO_POST_ON_DENY'] = True
    r = client.post('/api/security/events', headers=api_key,
                     json={'student': 'lsy', 'src_ip': '203.0.113.9', 'decision': 'deny',
                           'severity': 'High', 'reason': '차단 테스트', 'users': 'victim',
                           'fail_count': 5})
    assert r.status_code == 201
    assert r.get_json()['post_id'] is not None
