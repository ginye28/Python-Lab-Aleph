"""회원가입/로그인 — 잠금(423), 브루트포스 자동 차단, 실패 카운터, GELF·seclog 신호."""
import os


def register(client, username, password='PW12345!'):
    return client.post('/api/auth/register', json={'username': username, 'password': password})


def login(client, username, password='PW12345!', ip=None):
    """ip 를 넘기면 그 출발지 IP 로 요청한다 — 로그인 실패 카운터는 IP 별로
    프로세스 메모리에 쌓이므로(모듈 전역 dict), 테스트마다 다른 IP 를 써서
    서로 다른 테스트의 실패 횟수가 섞이지 않게 한다."""
    kwargs = {'json': {'username': username, 'password': password}}
    if ip:
        kwargs['environ_overrides'] = {'REMOTE_ADDR': ip}
    return client.post('/api/auth/login', **kwargs)


def test_register_then_duplicate_is_rejected(app_client):
    _app, client = app_client
    assert register(client, 'alice').status_code == 201
    assert register(client, 'alice').status_code == 400


def test_register_without_username_or_password_is_400(app_client):
    _app, client = app_client
    r = client.post('/api/auth/register', json={'username': '', 'password': ''})
    assert r.status_code == 400


def test_login_success_returns_token_and_role(app_client):
    _app, client = app_client
    register(client, 'bob')
    r = login(client, 'bob')
    assert r.status_code == 200
    body = r.get_json()
    assert body['access_token']
    assert body['role_key'] == 'user'


def test_login_wrong_password_is_401_and_increments_failed_logins(app_client, api_key):
    _app, client = app_client
    register(client, 'carol')
    login(client, 'carol', 'WRONG', ip='203.0.113.10')
    login(client, 'carol', 'WRONG', ip='203.0.113.10')
    users = client.get('/api/admin/users', headers=api_key).get_json()['users']
    carol = next(u for u in users if u['username'] == 'carol')
    assert carol['failed_logins'] == 2


def test_login_success_resets_failed_logins(app_client, api_key):
    _app, client = app_client
    register(client, 'dan')
    login(client, 'dan', 'WRONG', ip='203.0.113.11')
    login(client, 'dan', ip='203.0.113.11')
    users = client.get('/api/admin/users', headers=api_key).get_json()['users']
    dan = next(u for u in users if u['username'] == 'dan')
    assert dan['failed_logins'] == 0


def test_bruteforce_threshold_autoblocks_ip_and_reports(app_client, gelf_outbox):
    """LOGIN_FAIL_THRESHOLD(5)번 연속 실패하면 그 IP 가 즉시 차단된다."""
    _app, client = app_client
    register(client, 'eve')
    ip = '203.0.113.12'
    for _ in range(4):
        r = login(client, 'eve', 'WRONG', ip=ip)
        assert r.status_code == 401
    r = login(client, 'eve', 'WRONG', ip=ip)
    assert r.status_code == 403
    assert r.get_json()['blocked'] is True
    rules = [p for p, _ in gelf_outbox]
    assert any(b'login-bruteforce' in p for p in rules)


def test_locked_account_rejected_even_with_correct_password(app_client, api_key):
    _app, client = app_client
    register(client, 'frank')
    client.post('/api/admin/lock', headers=api_key, json={'username': 'frank'})
    r = login(client, 'frank')
    assert r.status_code == 423
    assert r.get_json()['locked'] is True


def test_unlock_allows_login_again(app_client, api_key):
    _app, client = app_client
    register(client, 'gina')
    client.post('/api/admin/lock', headers=api_key, json={'username': 'gina'})
    client.post('/api/admin/unlock', headers=api_key, json={'username': 'gina'})
    assert login(client, 'gina').status_code == 200


def test_login_success_sends_gelf_and_writes_seclog(app_client, gelf_outbox):
    app, client = app_client
    register(client, 'hank')
    login(client, 'hank')
    rules = [p for p, _ in gelf_outbox]
    assert any(b'login-success' in p for p in rules)

    path = app.config['SECURITY_LOG_PATH']
    assert os.path.exists(path)
    lines = open(path, encoding='utf-8').read().splitlines()
    assert any('login_success user=hank' in l for l in lines)


def test_seclog_sanitizes_log_injection_in_username(app_client):
    app, client = app_client
    login(client, 'evil\nFAKE_LINE injected=1', 'x', ip='203.0.113.13')
    lines = open(app.config['SECURITY_LOG_PATH'], encoding='utf-8').read().splitlines()
    assert not any('FAKE_LINE injected=1' == l.strip() for l in lines)
    assert any('evil_FAKE_LINE' in l for l in lines)


def test_unknown_user_login_failure_still_logged(app_client):
    app, client = app_client
    login(client, 'nosuchuser', 'x', ip='203.0.113.14')
    lines = open(app.config['SECURITY_LOG_PATH'], encoding='utf-8').read().splitlines()
    assert any('login_failed user=nosuchuser' in l for l in lines)
