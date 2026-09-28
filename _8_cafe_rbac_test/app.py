"""엔트리포인트 — 앱 팩토리(create_app) 패턴.

구조
  config.py       설정(.env 로딩)
  extensions.py   db · jwt 인스턴스
  models/         User · Post · SecurityEvent · Incident · BlockedIP
  controllers/    page · auth · post · security · public · admin · gold · access (블루프린트)
  templates/      화면

실행:  python app.py   →  http://127.0.0.1:5000
"""
from flask import Flask, jsonify, request
from sqlalchemy import inspect, text

from config import Config
from controllers import all_blueprints
from controllers.gelf import send_gelf
from controllers.rbac import client_ip, is_trusted_automation
from extensions import db, jwt
from models import BlockedIP

# 기존 표에 나중에 추가된 컬럼들 — {표 이름: {컬럼 이름: ALTER 문}}
_ADDED_COLUMNS = {
    'cafe_users': {
        'role_granted_by': "ALTER TABLE cafe_users ADD COLUMN role_granted_by VARCHAR(80) NULL",
        'role_granted_at': "ALTER TABLE cafe_users ADD COLUMN role_granted_at DATETIME NULL",
        'role_reason': "ALTER TABLE cafe_users ADD COLUMN role_reason VARCHAR(200) NULL",
        'is_locked': "ALTER TABLE cafe_users ADD COLUMN is_locked BOOLEAN NOT NULL DEFAULT 0",
        'locked_at': "ALTER TABLE cafe_users ADD COLUMN locked_at DATETIME NULL",
        'lock_reason': "ALTER TABLE cafe_users ADD COLUMN lock_reason VARCHAR(200) NULL",
        'failed_logins': "ALTER TABLE cafe_users ADD COLUMN failed_logins INT NOT NULL DEFAULT 0",
    },
    'security_events': {
        'fail_count': "ALTER TABLE security_events ADD COLUMN fail_count INT NOT NULL DEFAULT 0",
        'users': "ALTER TABLE security_events ADD COLUMN users VARCHAR(255) NULL",
        'last_seen': "ALTER TABLE security_events ADD COLUMN last_seen VARCHAR(32) NULL",
        'window_min': "ALTER TABLE security_events ADD COLUMN window_min INT NULL",
        'source': "ALTER TABLE security_events ADD COLUMN source VARCHAR(50) NULL",
        'generated_at': "ALTER TABLE security_events ADD COLUMN generated_at VARCHAR(32) NULL",
    },
}


def _ensure_added_columns():
    """이미 만들어져 있는 표에 나중에 생긴 컬럼을 채워 넣는다(가벼운 자동 마이그레이션).

    db.create_all() 은 '없는 표'만 만들고 기존 표는 손대지 않는다. 이 실습은
    마이그레이션 도구(alembic)를 쓰지 않으므로, 예전 스키마로 만들어진 표를 쓰던
    사람도 앱만 다시 켜면 되도록 여기서 컬럼 유무를 보고 없을 때만 붙인다."""
    inspector = inspect(db.engine)
    for table, columns in _ADDED_COLUMNS.items():
        if not inspector.has_table(table):
            continue   # db.create_all() 이 이미 최신 스키마로 만들었을 것이다.
        existing = {c['name'] for c in inspector.get_columns(table)}
        for name, ddl in columns.items():
            if name in existing:
                continue
            db.session.execute(text(ddl))
            db.session.commit()
            print(f'[마이그레이션] {table} 에 {name} 컬럼을 추가했습니다.')


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    jwt.init_app(app)

    for bp in all_blueprints:
        app.register_blueprint(bp)

    with app.app_context():
        db.create_all()   # cafe_incidents 처럼 없는 표는 여기서 새로 만들어진다.
        _ensure_added_columns()

    @app.before_request
    def block_ip_guard():
        """차단된 IP 실차단(active response) — 미들웨어가 앱에 닿기 전에 403 으로 되돌린다.

        - /api/admin/* 는 예외로 둔다. 그래야 관리자(사람 또는 회수봇)가 자기 자신을
          막힌 IP 로 만들어 복구 불능이 되는 상황 없이 계속 차단/해제를 할 수 있다.
        - ★ 유효한 API 키를 제시한 자동화(SOAR) 요청도 예외다. 브루트포스 대응으로
          SOAR 가 자기 자신의 IP(예: 127.0.0.1)를 차단하면, 같은 호스트에서 오는 보안
          봇의 신고·조회 호출까지 403 이 되어 봇이 스스로를 잠그게 된다(자기차단).
          사람이 아닌 인증된 봇은 차단 대상이 아니다.
        - 매 요청 cafe_blocked_ips 표를 조회한다. 실습 규모에선 충분하고, 실서비스는
          캐시(Redis)나 방화벽(nftables) 계층으로 올려야 한다."""
        if request.path.startswith('/api/admin'):
            return None
        if is_trusted_automation():
            return None
        ip = client_ip()
        if ip and db.session.get(BlockedIP, ip):
            # S5 지속성 탐지 — 차단됐는데도 계속 두드리는 것을 신고한다.
            # 403 만 주고 끝내면 '공격이 멈췄는지'를 알 수 없다.
            try:
                send_gelf(f"blocked ip retried {request.path[:80]}", rule='blocked-retry',
                          src_ip=ip, path=request.path[:120], code=403)
            except Exception:
                pass
            return jsonify({"msg": "차단된 IP 입니다(관리자에게 문의).", "ip": ip, "blocked": True}), 403

    @app.after_request
    def web_scan_probe(response):
        """스캐너(nikto·dirbuster 등)는 없는 경로에 404 를 대량 유발한다.
        404 를 GELF(rule='web-scan')로 신고 → Graylog src_ip 집계가 '한 IP 404 폭주'를 탐지."""
        try:
            if response.status_code == 404 and not request.path.startswith('/api/admin'):
                send_gelf(f"404 probe {request.path[:80]}", rule='web-scan',
                          src_ip=client_ip(), path=request.path[:120], code=404)
        except Exception:
            pass
        return response

    return app


app = create_app()


if __name__ == '__main__':
    # 기본값은 127.0.0.1 — 이 PC 안에서만 접속된다.
    # 리눅스 VM 등 같은 네트워크의 다른 장비에서 붙어야 하면 .env 에
    # FLASK_HOST=0.0.0.0 을 넣는다. 단, debug=True 인 채로 밖에 열면
    # Werkzeug 디버거가 노출돼 원격 코드 실행이 가능해지므로
    # 외부에 열 때는 FLASK_DEBUG=0 도 같이 넣어 디버거를 끈다.
    app.run(
        host=app.config.get('FLASK_HOST', '127.0.0.1'),
        debug=app.config.get('FLASK_DEBUG', True),
        port=5000,
    )
