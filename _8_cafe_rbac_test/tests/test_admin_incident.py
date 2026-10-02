"""관리자 API — 등급 부여/회수, 정책 위반 조회, IP 차단, 계정 잠금, 인시던트 티켓."""
import time


def register(client, username, password='PW12345!'):
    return client.post('/api/auth/register', json={'username': username, 'password': password})


def test_grant_requires_api_key_only(app_client, api_key):
    _app, client = app_client
    register(client, 'badguy')
    assert client.post('/api/admin/grant', json={'username': 'badguy', 'role': 'admin'}).status_code == 401
    r = client.post('/api/admin/grant', headers=api_key,
                     json={'username': 'badguy', 'role': 'admin', 'reason': '과잉권한 테스트'})
    assert r.status_code == 200
    users = client.get('/api/admin/users?role=admin', headers=api_key).get_json()['users']
    bad = next(u for u in users if u['username'] == 'badguy')
    assert bad['role_key'] == 'admin'
    assert bad['role_reason'] == '과잉권한 테스트'
    assert bad['role_granted_at']


def test_revoke_requires_api_key_only_and_is_idempotent(app_client, api_key):
    _app, client = app_client
    register(client, 'overpriv')
    client.post('/api/admin/grant', headers=api_key, json={'username': 'overpriv', 'role': 'admin'})
    assert client.post('/api/admin/revoke', json={'username': 'overpriv'}).status_code == 401
    r = client.post('/api/admin/revoke', headers=api_key, json={'username': 'overpriv'})
    assert r.status_code == 200
    assert r.get_json()['new_role'] == '일반'


def test_violations_lists_admins_outside_allowlist(app_client, api_key):
    _app, client = app_client
    register(client, 'rogue')
    client.post('/api/admin/grant', headers=api_key, json={'username': 'rogue', 'role': 'admin'})
    r = client.get('/api/admin/violations?allowlist=admin', headers=api_key)
    assert any(u['username'] == 'rogue' for u in r.get_json()['violations'])


def test_lock_requires_dual_auth_and_login_returns_423(app_client, api_key):
    _app, client = app_client
    register(client, 'victim')
    assert client.post('/api/admin/lock', json={'username': 'victim'}).status_code == 401
    r = client.post('/api/admin/lock', headers=api_key, json={'username': 'victim', 'fail_count': 7})
    assert r.status_code == 200
    assert r.get_json()['event_id'] is not None
    r2 = client.post('/api/admin/lock', headers=api_key, json={'username': 'victim'})
    assert r2.get_json()['changed'] is False


def test_block_unblock_ip(app_client, api_key):
    _app, client = app_client
    r = client.post('/api/admin/block', headers=api_key, json={'ip': '192.0.2.1', 'reason': 'test'})
    assert r.status_code == 200 and r.get_json()['blocked'] is True
    r2 = client.get('/api/admin/blocked', headers=api_key)
    assert any(b['ip'] == '192.0.2.1' for b in r2.get_json()['blocked'])
    client.post('/api/admin/unblock', headers=api_key, json={'ip': '192.0.2.1'})
    r3 = client.get('/api/admin/blocked', headers=api_key)
    assert not any(b['ip'] == '192.0.2.1' for b in r3.get_json()['blocked'])


def test_blocked_ip_gets_403_except_on_admin_api(app_client, api_key):
    _app, client = app_client
    client.post('/api/admin/block', headers=api_key, json={'ip': '203.0.113.50'})
    r = client.get('/api/auth/me', environ_overrides={'REMOTE_ADDR': '203.0.113.50'})
    assert r.status_code == 403
    # 관리자 API 는 차단 미들웨어의 예외 대상이다.
    r2 = client.get('/api/admin/blocked', headers=api_key,
                     environ_overrides={'REMOTE_ADDR': '203.0.113.50'})
    assert r2.status_code == 200


def test_incident_create_update_close(app_client, api_key):
    _app, client = app_client
    src_ip = '203.0.113.60'
    client.post('/api/security/events', headers=api_key,
                json={'student': 'lsy', 'src_ip': src_ip, 'decision': 'deny',
                      'severity': 'High', 'reason': 'test'})
    r = client.post('/api/admin/incident', headers=api_key, json={'src_ip': src_ip, 'student': 'lsy'})
    assert r.status_code == 201
    inc = r.get_json()['incident']
    assert '[타임라인]' in inc['summary']
    assert inc['event_count'] >= 1

    r2 = client.post('/api/admin/incident', headers=api_key, json={'src_ip': src_ip})
    assert r2.status_code == 200 and r2.get_json()['created'] is False

    rows = client.get('/api/admin/incidents?status=open', headers=api_key).get_json()['incidents']
    assert sum(1 for i in rows if i['src_ip'] == src_ip) == 1

    r3 = client.post('/api/admin/incident/close', headers=api_key, json={'id': inc['id']})
    assert r3.get_json()['incident']['status'] == 'closed'

    assert client.post('/api/admin/incident/close', headers=api_key, json={'id': 999999}).status_code == 404


def test_incident_severity_never_decreases_and_boundary_excludes_closed_events(app_client, api_key):
    _app, client = app_client
    src_ip = '198.51.100.90'
    client.post('/api/security/events', headers=api_key,
                json={'student': 'lsy', 'src_ip': src_ip, 'decision': 'deny', 'severity': 'Low'})

    r = client.post('/api/admin/incident', headers=api_key,
                     json={'src_ip': src_ip, 'severity': 'Critical'})
    inc = r.get_json()['incident']
    assert inc['severity'] == 'Critical'

    client.post('/api/admin/incident/close', headers=api_key, json={'id': inc['id']})
    time.sleep(1.1)   # created_at 은 초 단위 server_default 라 같은 초 안이면 경계가 어긋난다

    client.post('/api/security/events', headers=api_key,
                json={'student': 'lsy', 'src_ip': src_ip, 'decision': 'deny', 'severity': 'Medium'})
    r2 = client.post('/api/admin/incident', headers=api_key, json={'src_ip': src_ip})
    inc2 = r2.get_json()['incident']
    assert r2.get_json()['created'] is True
    assert inc2['event_count'] == 1          # 종료 이전 사건을 다시 흡수하지 않음
    assert inc2['severity'] == 'Medium'       # 옛 Critical 을 이어받지 않음

    r3 = client.post('/api/admin/incident', headers=api_key, json={'src_ip': src_ip, 'severity': 'Low'})
    assert r3.get_json()['incident']['severity'] == 'Medium'   # 더 낮은 값에 내려가지 않음


def test_auth_boundary_rejects_missing_key(app_client):
    _app, client = app_client
    assert client.post('/api/admin/lock', json={'username': 'x'}).status_code == 401
    assert client.get('/api/admin/incidents').status_code == 401
    assert client.get('/api/admin/violations').status_code == 401
