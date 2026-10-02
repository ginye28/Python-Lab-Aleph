"""등급별 접근 제어(RBAC) — 골드/관리자 API 와 /api/access/* 확인 엔드포인트."""


def register(client, username, password='PW12345!'):
    return client.post('/api/auth/register', json={'username': username, 'password': password})


def login_token(client, username, password='PW12345!'):
    r = client.post('/api/auth/login', json={'username': username, 'password': password})
    return {'Authorization': f"Bearer {r.get_json()['access_token']}"}


def test_gold_posts_requires_login(app_client):
    _app, client = app_client
    assert client.get('/api/gold/posts').status_code == 401


def test_gold_posts_rejects_general_user(app_client):
    _app, client = app_client
    register(client, 'u1')
    token = login_token(client, 'u1')
    r = client.get('/api/gold/posts', headers=token)
    assert r.status_code == 403
    assert r.get_json()['required_role_name'] == '골드'


def test_gold_posts_allows_gold_user(app_client, api_key):
    _app, client = app_client
    register(client, 'u2')
    client.post('/api/admin/grant', headers=api_key, json={'username': 'u2', 'role': 'gold'})
    token = login_token(client, 'u2')
    r = client.get('/api/gold/posts', headers=token)
    assert r.status_code == 200
    assert 'posts' in r.get_json()


def test_access_gold_and_access_admin_endpoints(app_client, api_key):
    _app, client = app_client
    register(client, 'u3')
    token = login_token(client, 'u3')
    assert client.get('/api/access/gold', headers=token).status_code == 403
    assert client.get('/api/access/admin', headers=token).status_code == 403

    client.post('/api/admin/grant', headers=api_key, json={'username': 'u3', 'role': 'admin'})
    admin_token = login_token(client, 'u3')
    assert client.get('/api/access/gold', headers=admin_token).status_code == 200
    assert client.get('/api/access/admin', headers=admin_token).status_code == 200


def test_admin_update_user_is_jwt_only_not_api_key(app_client, api_key):
    """PUT /api/admin/users/<id> 는 사람(JWT 관리자) 전용 — X-API-Key 는 안 통한다."""
    _app, client = app_client
    register(client, 'target')
    target_id = next(u for u in client.get('/api/admin/users', headers=api_key)
                      .get_json()['users'] if u['username'] == 'target')['id']
    r = client.put(f'/api/admin/users/{target_id}', headers=api_key, json={'role': 1})
    assert r.status_code == 401


def test_admin_cannot_demote_self(app_client, api_key):
    _app, client = app_client
    register(client, 'selfadmin')
    client.post('/api/admin/grant', headers=api_key, json={'username': 'selfadmin', 'role': 'admin'})
    token = login_token(client, 'selfadmin')
    me = client.get('/api/auth/me', headers=token).get_json()
    r = client.put(f"/api/admin/users/{me['id']}", headers=token, json={'role': 0})
    assert r.status_code == 400


def test_admin_cannot_delete_self(app_client, api_key):
    _app, client = app_client
    register(client, 'selfadmin2')
    client.post('/api/admin/grant', headers=api_key, json={'username': 'selfadmin2', 'role': 'admin'})
    token = login_token(client, 'selfadmin2')
    me = client.get('/api/auth/me', headers=token).get_json()
    r = client.delete(f"/api/admin/users/{me['id']}", headers=token)
    assert r.status_code == 400


def test_post_edit_requires_ownership(app_client):
    _app, client = app_client
    register(client, 'author')
    register(client, 'other')
    author_token = login_token(client, 'author')
    other_token = login_token(client, 'other')
    client.post('/api/posts', headers=author_token,
                json={'title': 't', 'content': 'c', 'category': '일반'})
    post_id = client.get('/api/posts').get_json()['posts'][0]['id']
    assert client.put(f'/api/posts/{post_id}', headers=other_token,
                       json={'title': 'hacked'}).status_code == 403
    assert client.put(f'/api/posts/{post_id}', headers=author_token,
                       json={'title': 'edited'}).status_code == 200
