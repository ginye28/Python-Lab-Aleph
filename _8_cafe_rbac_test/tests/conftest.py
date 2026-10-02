"""테스트 공통 설정 — 테스트가 실제 SIEM 으로 GELF 를 쏘지 않게 막고,
매 테스트마다 깨끗한 sqlite DB 로 앱을 띄워 준다.

`send_gelf` 는 UDP 로 fire-and-forget 전송한다. 그래서 pytest 를 한 번 돌릴
때마다 실습용 Graylog 에 가짜 로그인 기록이 실제로 쌓일 수 있다. 그래서
`controllers.gelf` 모듈이 쓰는 socket 만 조용한 대체품으로 바꾼다. 표준 socket
모듈 자체는 건드리지 않으므로 다른 코드에는 영향이 없다.

보낸 내용은 `gelf_outbox` 픽스처로 확인할 수 있다.
"""
from datetime import timedelta

import pytest


class _RecordingSocket:
    """보내는 대신 기록만 한다."""

    def __init__(self, box):
        self._box = box

    def sendto(self, payload, addr):
        self._box.append((payload, addr))

    def close(self):
        pass


class _StubSocketModule:
    """`controllers.gelf` 가 기대하는 최소한의 socket 모듈 흉내."""

    AF_INET = 2
    SOCK_DGRAM = 2

    def __init__(self):
        self.sent = []

    def socket(self, *args, **kwargs):
        return _RecordingSocket(self.sent)

    def gethostname(self):
        return 'test-host'


@pytest.fixture(autouse=True)
def gelf_outbox(monkeypatch):
    """모든 테스트에서 GELF 전송을 가로챈다. 반환값은 (payload, 주소) 목록."""
    import controllers.gelf as gelf_mod

    stub = _StubSocketModule()
    monkeypatch.setattr(gelf_mod, 'socket', stub)
    return stub.sent


@pytest.fixture
def app_client(tmp_path):
    """(app, test_client) 쌍 — 매 테스트마다 빈 sqlite DB 로 새로 띄운다."""
    from app import create_app
    from extensions import db

    class TestConfig:
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'test.db'}"
        SQLALCHEMY_TRACK_MODIFICATIONS = False
        JWT_SECRET_KEY = 'test-secret-key'
        JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
        # 실서비스 기본값과 같다(ADMIN_API_KEY 를 따로 안 정하면 SECURITY_API_KEY 를
        # 같이 쓴다 — config.py 참고) — 두 값을 같게 둬서 테스트의 `api_key` 하나로
        # /api/security/* 와 /api/admin/* 양쪽을 모두 호출할 수 있게 한다.
        SECURITY_API_KEY = 'test-api-key'
        ADMIN_API_KEY = 'test-api-key'
        ADMIN_ALLOWLIST = []
        AUTO_POST_ON_DENY = False
        LOGIN_FAIL_THRESHOLD = 5
        SECURITY_WEBHOOK_URL = 'http://example.invalid/webhook'
        STUDENT_NAME = 'tester'
        GELF_HOST = 'example.invalid'
        GELF_PORT = 12201
        SECURITY_LOG_PATH = str(tmp_path / 'security.log')
        PUBLIC_API_KEY = None
        PUBLIC_API_URL = 'http://example.invalid/'
        FLASK_HOST = '127.0.0.1'
        FLASK_DEBUG = False

    application = create_app(TestConfig)
    yield application, application.test_client()
    with application.app_context():
        db.session.remove()
        db.engine.dispose()


@pytest.fixture
def api_key():
    return {'X-API-Key': 'test-api-key'}
