from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity,
    verify_jwt_in_request,
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
import json
import os
import socket
import requests
from dotenv import load_dotenv

load_dotenv()   # 상위 폴더의 .env 를 환경변수로 올린다

app = Flask(__name__)

# ── DB 접속 정보 ──────────────────────────────────────
# 값은 .env 에서 읽고, 없으면 docker-compose 의 기본값과 동일하게 동작한다.
# host 는 127.0.0.1 로 고정한다. Windows 에서 localhost 는 IPv6(::1) 로 먼저
# 해석돼 도커 포트포워딩과 어긋나는 경우가 있다.
DB_USER = os.environ.get("MYSQL_USER", "root")
DB_PASSWORD = os.environ.get("MYSQL_ROOT_PASSWORD", "")  # 기본값 없음 - .env 에서만 읽는다
DB_HOST = os.environ.get("MYSQL_HOST", "127.0.0.1")
DB_PORT = os.environ.get("MYSQL_PORT", "3306")
DB_NAME = os.environ.get("MYSQL_DATABASE", "github_db")

app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get("JWT_SECRET_KEY", "dev-only-change-me")
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=2)

# 실습과제: 게시판 REST API 를 호출할 때 쓰는 키. 소스에 직접 쓰지 않고 .env 에서 읽는다.
SECURITY_API_KEY = os.environ.get("SECURITY_API_KEY", "dev-only-change-me")
# 과잉권한 회수봇(privilege_revoke_bot.py) 이 /api/admin/users, /api/admin/revoke 를
# 호출할 때 쓰는 키. 따로 안 정해두면 SECURITY_API_KEY 를 같이 쓴다.
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY", SECURITY_API_KEY)

# ----------------- IP 차단 요구사항 +a) 로그인 실패 자동 차단 -----------------
# 같은 IP 에서 이만큼 연속으로 로그인 실패하면 즉시 차단하고 기존
# security-alert-bot(n8n) 경로로 신고한다. alert_sender.py 와 이름을 맞춘다.
LOGIN_FAIL_THRESHOLD = int(os.environ.get("LOGIN_FAIL_THRESHOLD", "5"))
SECURITY_WEBHOOK_URL = os.environ.get(
    "SECURITY_WEBHOOK_URL", "http://localhost:5678/webhook/security-events"
)
STUDENT_NAME = os.environ.get("STUDENT_NAME", "본인이름으로_바꾸세요")
# Graylog 직통 신고 (privilege_revoke_bot.py 의 send_gelf 와 같은 방식 — GELF UDP).
GRAYLOG_HOST = os.environ.get("GRAYLOG_HOST", "localhost")
GRAYLOG_PORT = int(os.environ.get("GRAYLOG_PORT", "12201"))
# admin 을 가져도 되는 계정(정책 허용목록). 위반 조회·회수봇의 기준이 된다.
# 쉼표로 구분: "admin,instructor". 비어 있으면 모든 admin 을 위반으로 본다.
ADMIN_ALLOWLIST = [u.strip() for u in os.environ.get("ADMIN_ALLOWLIST", "").split(',') if u.strip()]
# 거부(deny) 이벤트가 들어오면 게시판에 '보안' 공지글을 자동 등록할지.
AUTO_POST_ON_DENY = os.environ.get("AUTO_POST_ON_DENY", "0") == "1"


def _mask(value):
    """진단 로그용 — 값 전체를 찍지 않고 앞뒤 몇 글자·길이만 보여준다."""
    if not value:
        return "(비어있음)"
    if len(value) <= 8:
        return f"{value[:2]}…(길이 {len(value)})"
    return f"{value[:4]}…{value[-4:]} (길이 {len(value)})"


def check_admin_api_key():
    """X-API-Key 를 ADMIN_API_KEY 와 비교한다. 401 원인을 서버 터미널에서 바로
    확인할 수 있도록, 불일치할 때만 두 값의 길이·앞뒤 글자를 진단으로 찍는다
    (전체 값은 절대 찍지 않는다). 문제를 못 찾으면 이 print 를 지운다."""
    received = request.headers.get('X-API-Key')
    if received == ADMIN_API_KEY:
        return True
    print(
        "[진단] X-API-Key 불일치\n"
        f"       요청으로 받은 값 : {_mask(received)}\n"
        f"       .env 의 ADMIN_API_KEY : {_mask(ADMIN_API_KEY)}\n"
        "       -> 길이나 앞뒤 글자가 다르면 Postman 헤더 값을 .env 값으로 다시 복붙하세요.\n"
        "       -> '(비어있음)' 이면 헤더 자체가 안 왔다는 뜻 — Postman 에서 해당 헤더 체크박스가 켜져 있는지 확인하세요."
    )
    return False


db = SQLAlchemy(app)
jwt = JWTManager(app)

# ----------------- 미니 실습: RBAC 등급 -----------------
# 일반 0 / 골드 1 / 관리자 2  — 숫자가 클수록 넓은 권한.
# 테이블 이름은 원본 게시판(_7_board_test)의 users/posts 와 겹치지 않도록
# cafe_ 접두사를 붙였다. 같은 MySQL 스키마(github_db)를 같이 쓰기 때문이다.
ROLE_GENERAL = 0   # 일반 등급 — 최초 가입
ROLE_GOLD = 1      # 골드 등급 — 중간 관리자
ROLE_ADMIN = 2     # 관리자

ROLE_NAMES = {ROLE_GENERAL: '일반', ROLE_GOLD: '골드', ROLE_ADMIN: '관리자'}
# 회수봇이 role=admin 처럼 영문 이름으로 필터링을 요청할 때 쓰는 역방향 맵.
# 강사님 저장소(_7_board_test)는 등급을 'user'/'gold'/'admin' 문자열로 쓴다.
# 이 앱은 숫자(0/1/2)로 두되, 그쪽 이름도 그대로 받아 같은 요청이 통하게 한다.
ROLE_NAME_TO_VALUE = {
    'general': ROLE_GENERAL, 'user': ROLE_GENERAL,
    'gold': ROLE_GOLD,
    'admin': ROLE_ADMIN,
}
# 응답에도 같은 문자열을 실어 준다(role_key) — 숫자만 보면 그쪽 도구가 못 읽는다.
ROLE_KEYS = {ROLE_GENERAL: 'user', ROLE_GOLD: 'gold', ROLE_ADMIN: 'admin'}


def _parse_role(value):
    """'admin' 같은 이름과 2 같은 숫자를 모두 받아 등급 숫자로 바꾼다. 모르면 None."""
    if isinstance(value, str) and not value.strip().isdigit():
        return ROLE_NAME_TO_VALUE.get(value.strip().lower())
    try:
        role = int(value)
    except (TypeError, ValueError):
        return None
    return role if role in ROLE_NAMES else None

# ----------------- Database Models -----------------
class User(db.Model):
    __tablename__ = 'cafe_users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    # 가입 시 무조건 0(일반)으로 시작한다. 등급 변경은 관리자 페이지에서만 가능.
    role = db.Column(db.Integer, nullable=False, default=ROLE_GENERAL)
    # 관리자 등급을 누가 부여했는지 기록 — 회수봇이 허용목록 밖 admin(=부여 근거가 없거나
    # 의심스러운 계정)을 탐지할 때 참고한다. 일반/골드로 내려가면 다시 비운다.
    role_granted_by = db.Column(db.String(80), nullable=True)
    # 감사(audit): 언제·왜 이 등급이 됐는가.
    role_granted_at = db.Column(db.DateTime, nullable=True)
    role_reason = db.Column(db.String(200), nullable=True)

    # ── 계정 잠금(account lockout) — 브루트포스 대응 ──
    # 로그인 실패가 임계를 넘으면 n8n(SOAR)이 잠근다. 잠긴 계정은 비번이 맞아도 423.
    is_locked = db.Column(db.Boolean, nullable=False, default=False, server_default='0')
    locked_at = db.Column(db.DateTime, nullable=True)
    lock_reason = db.Column(db.String(200), nullable=True)
    # 표시용 누적 실패 횟수(로그인 성공 시 0으로 초기화).
    failed_logins = db.Column(db.Integer, nullable=False, default=0, server_default='0')

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "role_name": ROLE_NAMES.get(self.role, '알수없음'),
            # 강사님 저장소와 같은 'user'/'gold'/'admin' 표기도 함께 준다.
            "role_key": ROLE_KEYS.get(self.role, 'unknown'),
            "role_granted_by": self.role_granted_by,
            "role_granted_at": self.role_granted_at.isoformat() if self.role_granted_at else None,
            "role_reason": self.role_reason,
            "is_locked": self.is_locked,
            "locked_at": self.locked_at.isoformat() if self.locked_at else None,
            "lock_reason": self.lock_reason,
            "failed_logins": self.failed_logins,
        }

class Post(db.Model):
    __tablename__ = 'cafe_posts'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False, default='일반')
    author_id = db.Column(db.Integer, db.ForeignKey('cafe_users.id'), nullable=False)
    author = db.relationship('User', backref=db.backref('posts', lazy=True))

class SecurityEvent(db.Model):
    __tablename__ = 'security_events'
    id = db.Column(db.Integer, primary_key=True)
    student = db.Column(db.String(80), nullable=False)
    src_ip = db.Column(db.String(45), nullable=False)
    decision = db.Column(db.String(10), nullable=False)   # 'allow' | 'deny'
    severity = db.Column(db.String(10))                   # 'Low' | 'Medium' | 'High'
    reason = db.Column(db.String(255))
    # 아래는 강사님 저장소(_7_board_test)의 security_events 와 필드를 맞춘 것.
    fail_count = db.Column(db.Integer, nullable=False, default=0, server_default='0')
    users = db.Column(db.String(255))        # 시도된 계정들
    last_seen = db.Column(db.String(32))     # 마지막 시도 시각(보낸 쪽 표기 그대로)
    window_min = db.Column(db.Integer)       # 집계 구간(분)
    source = db.Column(db.String(50), default='login_guard')   # 어느 탐지기가 보냈나
    generated_at = db.Column(db.String(32))  # 보낸 쪽이 만든 시각
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "student": self.student,
            "src_ip": self.src_ip,
            "decision": self.decision,
            "severity": self.severity,
            "reason": self.reason,
            "fail_count": self.fail_count,
            "users": self.users,
            "last_seen": self.last_seen,
            "window_min": self.window_min,
            "source": self.source,
            "generated_at": self.generated_at,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Incident(db.Model):
    """보안 인시던트(사고) 티켓 — 탐지·대응 결과를 한 건의 추적 단위로 남긴다.

    같은 출발지(src_ip)의 '열린' 티켓은 하나만 두고(중복 방지), 이벤트가 쌓이면
    요약을 갱신한다. 실무의 티켓(Jira/ServiceNow) 축소판 — 감사·인계에 쓴다.
    """
    __tablename__ = 'cafe_incidents'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    src_ip = db.Column(db.String(45), index=True)
    severity = db.Column(db.String(10), default='Medium')          # Low|Medium|High|Critical
    status = db.Column(db.String(12), default='open', index=True)  # open|closed
    summary = db.Column(db.Text)            # 자동 취합된, 사람이 읽는 요약(타임라인·조치)
    event_count = db.Column(db.Integer, default=0)
    actions = db.Column(db.String(255))     # 취해진 조치 요약
    student = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    closed_at = db.Column(db.DateTime)

    def to_dict(self):
        return {
            "id": self.id, "title": self.title, "src_ip": self.src_ip,
            "severity": self.severity, "status": self.status,
            "summary": self.summary, "event_count": self.event_count,
            "actions": self.actions, "student": self.student,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
        }


class BlockedIP(db.Model):
    """차단된 IP 목록(실차단). before_request 미들웨어가 매 요청 이 표를 보고 403 처리한다.

    관리자 페이지(또는 회수봇처럼 X-API-Key 를 쓰는 자동화)가 여기에 IP 를 추가하면,
    그 IP 로 들어오는 이후 요청은 관리자 API(/api/admin/*)를 제외하고 앱에 닿지 못한다.
    """
    __tablename__ = 'cafe_blocked_ips'
    ip = db.Column(db.String(45), primary_key=True)   # IPv6 까지 45자
    reason = db.Column(db.String(200))
    blocked_by = db.Column(db.String(80))
    blocked_at = db.Column(db.DateTime, server_default=db.func.now())

    def to_dict(self):
        return {
            "ip": self.ip,
            "reason": self.reason,
            "blocked_by": self.blocked_by,
            "blocked_at": self.blocked_at.isoformat() if self.blocked_at else None,
        }


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


def ensure_added_columns():
    """이미 만들어져 있는 표에 나중에 생긴 컬럼을 채워 넣는다(가벼운 자동 마이그레이션).

    db.create_all() 은 '없는 표'만 만들고 기존 표는 손대지 않는다. 이 실습은
    마이그레이션 도구(alembic)를 쓰지 않으므로, 예전 스키마로 만들어진 표를 쓰던
    사람도 앱만 다시 켜면 되도록 여기서 컬럼 유무를 보고 없을 때만 붙인다.
    """
    inspector = db.inspect(db.engine)
    for table, columns in _ADDED_COLUMNS.items():
        existing = {c['name'] for c in inspector.get_columns(table)}
        for name, ddl in columns.items():
            if name in existing:
                continue
            db.session.execute(db.text(ddl))
            db.session.commit()
            print(f'[마이그레이션] {table} 에 {name} 컬럼을 추가했습니다.')


with app.app_context():
    db.create_all()   # cafe_incidents 처럼 없는 표는 여기서 새로 만들어진다.
    ensure_added_columns()


def _client_ip():
    """요청의 실제 클라이언트 IP. 프록시(n8n 등) 뒤라면 X-Forwarded-For 첫 홉을 신뢰한다.
    (실습 한정 규칙 — 실서비스는 신뢰 프록시 목록으로 검증해야 스푸핑을 막는다.)"""
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr or ''


@app.before_request
def block_ip_guard():
    """차단된 IP 실차단(active response) — 미들웨어가 앱에 닿기 전에 403 으로 되돌린다.

    - /api/admin/* 는 예외로 둔다. 그래야 관리자(사람 또는 회수봇)가 자기 자신을
      막힌 IP 로 만들어 복구 불능이 되는 상황 없이 계속 차단/해제를 할 수 있다.
    - 매 요청 cafe_blocked_ips 표를 조회한다. 실습 규모에선 충분하고, 실서비스는
      캐시(Redis)나 방화벽(nftables) 계층으로 올려야 한다.
    """
    if request.path.startswith('/api/admin'):
        return None
    ip = _client_ip()
    if ip and db.session.get(BlockedIP, ip):
        return jsonify({"msg": "차단된 IP 입니다(관리자에게 문의).", "ip": ip, "blocked": True}), 403


def _require_admin():
    """관리자 전용 엔드포인트 공통 인증. admin_list_users 와 같은 방식으로

    ① X-API-Key 헤더가 ADMIN_API_KEY 와 일치하면 통과(자동화 봇용) — 이때는 (None, None) 반환.
    ② 없으면 JWT 로그인 + 관리자(2) 등급을 확인한다 — 통과하면 (User, None) 반환.
    실패하면 (None, (jsonify(...), status)) 형태로 바로 돌려줄 응답을 반환한다.
    """
    api_key = request.headers.get('X-API-Key')
    if api_key:
        if check_admin_api_key():
            return None, None
        return None, (jsonify({"msg": "인증 실패: X-API-Key 가 올바르지 않습니다."}), 401)

    verify_jwt_in_request()
    current_user = User.query.get(get_jwt_identity())
    if not current_user:
        return None, (jsonify({"msg": "사용자를 찾을 수 없습니다."}), 404)
    if current_user.role < ROLE_ADMIN:
        return None, (jsonify({
            "msg": f"접근 권한이 없습니다. (현재 등급: {ROLE_NAMES.get(current_user.role)}[{current_user.role}], "
                   f"필요 등급: {ROLE_NAMES.get(ROLE_ADMIN)}[{ROLE_ADMIN}] 이상)",
            "current_role": current_user.role,
            "required_role": ROLE_ADMIN,
        }), 403)
    return current_user, None


# ----------------- 요구사항 +a) IP 차단(block) -----------------
@app.route('/api/admin/block', methods=['POST'])
def admin_block_ip():
    """공격 IP 실차단(active response) → cafe_blocked_ips 에 추가. body: {ip, reason}
    이후 그 IP 로 오는 요청은 관리자 API 를 제외하고 미들웨어가 403 으로 막는다."""
    admin_user, err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    ip = (data.get('ip') or data.get('src_ip') or '').strip()
    if not ip:
        return jsonify({"msg": "ip(또는 src_ip) 는 필수입니다."}), 400

    actor = admin_user.username if admin_user else 'apikey'
    if db.session.get(BlockedIP, ip):
        return jsonify({"msg": "이미 차단된 IP 입니다.", "ip": ip, "blocked": True, "changed": False}), 200

    db.session.add(BlockedIP(ip=ip, reason=(data.get('reason') or f'관리자 차단 by {actor}')[:200], blocked_by=actor))
    # 감사기록: 대시보드(/security)에서도 보이도록 security_events 에 남긴다.
    event = SecurityEvent(
        student=(data.get('student') or actor)[:80],
        src_ip=ip,
        fail_count=int(data.get('fail_count') or 0),
        decision='deny',
        severity=data.get('severity', 'High'),
        reason=(data.get('reason') or f'IP 실차단: {ip}')[:255],
        users='',
        source=data.get('source', 'ip-guard'),
        generated_at=data.get('generated_at'),
    )
    db.session.add(event)
    db.session.commit()
    return jsonify({"msg": "IP 차단 완료", "ip": ip, "blocked": True, "changed": True,
                    "event_id": event.id, "blocked_by": actor}), 200


@app.route('/api/admin/unblock', methods=['POST'])
def admin_unblock_ip():
    """IP 차단 해제. body: {ip}"""
    _admin_user, err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    ip = (data.get('ip') or data.get('src_ip') or '').strip()
    if not ip:
        return jsonify({"msg": "ip 는 필수입니다."}), 400

    row = db.session.get(BlockedIP, ip)
    if row:
        db.session.delete(row)
        db.session.commit()
    return jsonify({"msg": "차단 해제 완료", "ip": ip, "blocked": False}), 200


@app.route('/api/admin/blocked', methods=['GET'])
def admin_list_blocked():
    """차단된 IP 목록."""
    _admin_user, err = _require_admin()
    if err:
        return err
    rows = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).all()
    return jsonify({"count": len(rows), "blocked": [r.to_dict() for r in rows]}), 200


# ----------------- 계정 잠금(account lockout) -----------------
@app.route('/api/admin/lock', methods=['POST'])
def admin_lock_account():
    """계정 잠금(브루트포스 대응) → is_locked=True. n8n 이 호출한다.
    body: {username, reason, student, src_ip, fail_count, severity}
    잠금이 실제로 일어나면 security_events 에 감사기록(source='login-guard')을 남긴다."""
    admin_user, err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    if not username:
        return jsonify({"msg": "username 은 필수입니다."}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"msg": f"없는 사용자: {username}"}), 404

    actor = admin_user.username if admin_user else 'apikey'
    if user.is_locked:
        return jsonify({"msg": "이미 잠긴 계정", "username": username,
                        "locked": True, "changed": False}), 200

    user.is_locked = True
    user.locked_at = datetime.now()
    user.lock_reason = (data.get('reason') or f'브루트포스 자동 잠금 by {actor}')[:200]
    event = SecurityEvent(
        student=(data.get('student') or actor)[:80],
        src_ip=data.get('src_ip') or '0.0.0.0',
        fail_count=int(data.get('fail_count') or 0),
        decision='deny',
        severity=data.get('severity', 'High'),
        reason=(data.get('reason') or f'계정 잠금: {username} (브루트포스)')[:255],
        users=username,
        source=data.get('source', 'login-guard'),
        generated_at=data.get('generated_at'),
    )
    db.session.add(event)
    db.session.commit()
    return jsonify({"msg": "계정 잠금 완료", "username": username, "locked": True,
                    "changed": True, "event_id": event.id, "locked_by": actor}), 200


@app.route('/api/admin/unlock', methods=['POST'])
def admin_unlock_account():
    """계정 잠금 해제 → is_locked=False + 실패 카운트 초기화. body: {username}"""
    admin_user, err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    if not username:
        return jsonify({"msg": "username 은 필수입니다."}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"msg": f"없는 사용자: {username}"}), 404

    user.is_locked = False
    user.failed_logins = 0
    user.lock_reason = None
    db.session.commit()
    return jsonify({"msg": "잠금 해제 완료", "username": username, "locked": False,
                    "unlocked_by": admin_user.username if admin_user else 'apikey'}), 200


# ----------------- 인시던트(보안 사고) 티켓 -----------------
_SEVERITY_RANK = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}


def _build_incident_summary(src_ip, events):
    """security_events 를 사람이 읽는 인시던트 요약(집계 + 타임라인)으로 취합한다."""
    by_source, actions = {}, set()
    worst = 'Low'
    lines = []
    for e in events:
        by_source[e.source] = by_source.get(e.source, 0) + 1
        if e.decision:
            actions.add(e.decision)
        if _SEVERITY_RANK.get(e.severity, 1) > _SEVERITY_RANK.get(worst, 1):
            worst = e.severity
        when = (e.created_at.strftime('%Y-%m-%d %H:%M:%S') if e.created_at
                else (e.generated_at or '?'))
        lines.append(f"- {when} [{e.severity}/{e.source}] {e.reason or ''} (users={e.users or '-'})")

    first = events[-1].created_at if events and events[-1].created_at else None
    last = events[0].created_at if events and events[0].created_at else None
    src_summary = ', '.join(f'{k}×{v}' for k, v in sorted(by_source.items(), key=lambda kv: str(kv[0])))
    action_text = ', '.join(sorted(actions)) or '없음'
    summary = (
        f"[인시던트 요약] 출발지 {src_ip}\n"
        f"- 관련 이벤트: {len(events)}건 ({src_summary})\n"
        f"- 최초/최종: {first} ~ {last}\n"
        f"- 취해진 조치: {action_text}\n"
        f"- 최고 심각도: {worst}\n"
        f"[타임라인]\n" + "\n".join(lines[:20])
    )
    return summary, worst, action_text, len(events)


@app.route('/api/admin/incident', methods=['POST'])
def admin_create_incident():
    """인시던트 티켓 생성/갱신. body: {src_ip, title?, severity?, student?, hours?}

    같은 src_ip 의 '열린' 티켓이 있으면 갱신하고(중복 방지), 없으면 새로 만든다.
    요약은 최근 hours(기본 24)시간의 security_events 를 자동으로 취합한다."""
    admin_user, err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    src_ip = (data.get('src_ip') or data.get('ip') or '').strip()
    if not src_ip:
        return jsonify({"msg": "src_ip 는 필수입니다."}), 400

    actor = admin_user.username if admin_user else 'apikey'
    hours = int(data.get('hours') or 24)
    since = datetime.now() - timedelta(hours=hours)
    events = (SecurityEvent.query
              .filter(SecurityEvent.src_ip == src_ip, SecurityEvent.created_at >= since)
              .order_by(SecurityEvent.created_at.desc()).all())
    summary, worst, actions, count = _build_incident_summary(src_ip, events)

    incident = Incident.query.filter_by(src_ip=src_ip, status='open').first()
    created = incident is None
    if created:
        incident = Incident(src_ip=src_ip, status='open')
        db.session.add(incident)

    incident.title = (data.get('title') or f'보안 인시던트: {src_ip} ({count}건)')[:200]
    incident.severity = data.get('severity') or worst
    incident.summary = summary
    incident.event_count = count
    incident.actions = actions[:255]
    incident.student = (data.get('student') or actor)[:50]
    db.session.commit()

    return jsonify({"msg": "인시던트 생성" if created else "인시던트 갱신",
                    "created": created,
                    "incident": incident.to_dict()}), (201 if created else 200)


@app.route('/api/admin/incidents', methods=['GET'])
def admin_list_incidents():
    """인시던트 목록. ?status=open|closed 로 거를 수 있다."""
    _admin_user, err = _require_admin()
    if err:
        return err

    status = request.args.get('status')
    query = Incident.query
    if status in ('open', 'closed'):
        query = query.filter_by(status=status)
    rows = query.order_by(Incident.updated_at.desc()).all()
    return jsonify({"count": len(rows), "incidents": [r.to_dict() for r in rows]}), 200


@app.route('/api/admin/incident/close', methods=['POST'])
def admin_close_incident():
    """인시던트 종료(status=closed). body: {id}"""
    _admin_user, err = _require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    try:
        incident_id = int(data.get('id') or 0)
    except (TypeError, ValueError):
        return jsonify({"msg": "id 가 올바르지 않습니다."}), 400

    incident = db.session.get(Incident, incident_id)
    if not incident:
        return jsonify({"msg": "없는 인시던트"}), 404

    incident.status = 'closed'
    incident.closed_at = datetime.now()
    db.session.commit()
    return jsonify({"msg": "인시던트 종료", "incident": incident.to_dict()}), 200


@app.route('/api/admin/violations', methods=['GET'])
def admin_list_violations():
    """정책 위반(허용목록 밖 관리자) 목록 — 회수봇이 참고용으로 쓸 수 있다.
    ?allowlist=admin,instructor 로 기준을 넘기면 .env 값보다 우선한다."""
    _admin_user, err = _require_admin()
    if err:
        return err

    param = request.args.get('allowlist')
    allow = ([u.strip() for u in param.split(',') if u.strip()] if param
             else ADMIN_ALLOWLIST)
    admins = User.query.filter_by(role=ROLE_ADMIN).all()
    bad = [u for u in admins if u.username not in allow]
    return jsonify({
        "allowlist": allow,
        "count": len(bad),
        "violations": [u.to_dict() for u in bad],
    }), 200


# 골드 전용 게시글 카테고리 (/api/gold/posts 가 이 값으로 거른다)
GOLD_CATEGORY = '골드'


# 같은 IP 의 연속 로그인 실패 횟수. 프로세스 메모리에만 두는 카운터라 서버를
# 재시작하면 초기화된다 — 실습 규모에선 충분하고, 실서비스는 Redis 등으로 옮겨야 한다.
_login_fail_counts = {}


def send_gelf(short_message, rule, **fields):
    """Graylog 로 GELF(UDP) 경보를 보낸다 — 실패해도 예외를 올리지 않는다.

    로그인 실패 같은 '앱만 아는 사건'을 SIEM 으로 흘려보내는 통로다.
    short_message 는 사람이 읽는 요약, rule 은 `_rule` 값(이벤트 필터 키),
    나머지 키워드 인자는 `_` 접두사가 붙어 커스텀 필드로 들어간다.
    """
    msg = {
        'version': '1.1', 'host': socket.gethostname(),
        'short_message': short_message, 'level': 4, '_rule': rule,
        '_student': STUDENT_NAME,
    }
    for key, value in fields.items():
        msg['_' + key] = value
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.sendto(json.dumps(msg).encode(), (GRAYLOG_HOST, GRAYLOG_PORT))
        finally:
            s.close()
    except OSError as e:
        # SIEM 이 꺼져 있어도 로그인 자체는 계속 동작해야 한다.
        print(f"[진단] Graylog 로 신고를 못 보냈습니다: {e}")


def _report_login_bruteforce(ip, fail_count):
    """연속 실패 임계치를 넘긴 IP 를 즉시 차단하고, 두 경로로 신고한다.

    ① 기존 security-alert-bot(n8n) 웹훅 — alert_sender.py 와 같은 payload 형태로
       보내서, 이미 Publish 된 워크플로(판정 → 거부인가? → 슬랙/디스코드/텔레그램 +
       게시판 저장)를 그대로 탄다.
    ② Graylog GELF 직통 신고.

    둘 다 n8n/Graylog 가 꺼져 있어도 로그인 응답 자체는 막히지 않도록 실패를 삼킨다.
    """
    if not db.session.get(BlockedIP, ip):
        db.session.add(BlockedIP(
            ip=ip,
            reason=f'로그인 {fail_count}회 연속 실패로 자동 차단',
            blocked_by='system',
        ))
        db.session.commit()

    payload = {
        "student": STUDENT_NAME,
        "alerts": [{
            "ip": ip,
            # 판정(Code) 노드의 DENY_LEVEL(기본 10) 이상이어야 deny 로 분류된다.
            "level": 10,
            "rule": "login-bruteforce",
            "fail_count": fail_count,
        }],
    }
    try:
        requests.post(SECURITY_WEBHOOK_URL, json=payload, timeout=5)
    except requests.RequestException as e:
        print(f"[진단] 로그인 실패 신고를 n8n 으로 못 보냈습니다: {e}")

    send_gelf(f"login bruteforce: '{ip}' failed {fail_count} times in a row",
              rule='login-bruteforce', src_ip=ip, fail_count=fail_count)


# ----------------- Auth Endpoints -----------------
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"msg": "아이디와 비밀번호를 입력해주세요."}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "이미 존재하는 아이디입니다."}), 400

    hashed_password = generate_password_hash(password)
    # 요구사항 3) 회원가입은 무조건 일반(0) 등급으로 시작한다.
    new_user = User(username=username, password=hashed_password, role=ROLE_GENERAL)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "회원가입이 완료되었습니다. (일반 등급으로 시작합니다)"}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    ip = _client_ip()

    # ① 잠긴 계정은 비밀번호가 맞아도 거부한다(423 Locked).
    if user and user.is_locked:
        send_gelf(f"login attempt on LOCKED account '{username}'",
                  rule='login-bruteforce', username=username, src_ip=ip, locked='1')
        return jsonify({
            "msg": "계정이 잠겨 있습니다. 관리자에게 문의하세요.",
            "locked": True,
        }), 423

    # ② 인증 실패 → 실패 카운트 증가 + Graylog 신고, 임계 넘으면 IP 자동 차단.
    if not user or not check_password_hash(user.password, password):
        if user:
            user.failed_logins = (user.failed_logins or 0) + 1
            db.session.commit()
        send_gelf(f"failed login for '{username}' from {ip}",
                  rule='login-bruteforce', username=username or '(unknown)',
                  src_ip=ip, count=1)

        fail_count = _login_fail_counts.get(ip, 0) + 1
        _login_fail_counts[ip] = fail_count

        if fail_count >= LOGIN_FAIL_THRESHOLD:
            _login_fail_counts.pop(ip, None)  # 차단됐으니 이 IP 카운터는 정리한다.
            _report_login_bruteforce(ip, fail_count)
            return jsonify({
                "msg": f"로그인 {fail_count}회 연속 실패로 IP 가 차단되었습니다.",
                "ip": ip,
                "blocked": True,
            }), 403

        return jsonify({"msg": "아이디 또는 비밀번호가 올바르지 않습니다."}), 401

    # ③ 성공 → 실패 카운터(메모리·DB) 초기화 후 토큰 발급.
    _login_fail_counts.pop(ip, None)
    if user.failed_logins:
        user.failed_logins = 0
        db.session.commit()

    # role 은 토큰 안에도 넣어 두지만(참고용), 실제 인가 검사는 매번 DB 를 다시 조회해서
    # 판단한다 — 관리자가 등급을 바꾸면 재로그인 없이도 바로 반영되게 하기 위해서다.
    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={"role": user.role, "username": user.username},
    )
    return jsonify({
        "access_token": access_token,
        "username": user.username,
        "role": user.role,
        "role_name": ROLE_NAMES.get(user.role, '알수없음'),
        "role_key": ROLE_KEYS.get(user.role, 'unknown'),
    }), 200


@app.route('/api/auth/me', methods=['GET'])
@jwt_required()
def me():
    # 헤더에 "로그인 유저명 + 등급" 을 항상 최신 DB 기준으로 보여주기 위한 엔드포인트.
    user = User.query.get(get_jwt_identity())
    if not user:
        return jsonify({"msg": "사용자를 찾을 수 없습니다."}), 404
    return jsonify(user.to_dict()), 200


def role_required(min_role):
    """요구사항 4/6) 접근에 필요한 최소 등급을 지정하는 데코레이터.

    등급이 모자라면 403 과 함께 '현재 등급 / 필요 등급' 을 그대로 돌려준다.
    프런트에서는 이 정보를 그대로 화면에 예외 메시지로 출력한다.
    """
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            user = User.query.get(get_jwt_identity())
            if not user:
                return jsonify({"msg": "사용자를 찾을 수 없습니다."}), 404
            if user.role < min_role:
                return jsonify({
                    "msg": f"접근 권한이 없습니다. (현재 등급: {ROLE_NAMES.get(user.role)}[{user.role}], "
                           f"필요 등급: {ROLE_NAMES.get(min_role)}[{min_role}] 이상)",
                    "current_role": user.role,
                    "current_role_name": ROLE_NAMES.get(user.role),
                    "required_role": min_role,
                    "required_role_name": ROLE_NAMES.get(min_role),
                }), 403
            return fn(user, *args, **kwargs)
        return wrapper
    return decorator


# ----------------- 골드 등급 전용 API -----------------
@app.route('/api/gold/posts', methods=['GET'])
@role_required(ROLE_GOLD)
def gold_posts(current_user):
    """골드 전용 게시글 목록.

    화면에서 메뉴를 숨기는 것만으로는 막은 게 아니다 — 주소창에 API 를 직접 쳐 보면
    그대로 열린다. 그래서 서버에서 한 번 더 등급을 검사한다."""
    rows = (Post.query.filter_by(category=GOLD_CATEGORY)
            .order_by(Post.id.desc()).limit(20).all())
    return jsonify({
        "count": len(rows),
        "posts": [{
            "id": p.id, "title": p.title, "content": p.content,
            "category": p.category,
            "author": p.author.username if p.author else 'Unknown',
        } for p in rows],
    }), 200


# ----------------- 등급별 접근 확인용 엔드포인트 -----------------
@app.route('/api/access/gold', methods=['GET'])
@role_required(ROLE_GOLD)
def access_gold(current_user):
    return jsonify({
        "msg": f"{current_user.username}님, 골드 라운지 접근이 허용되었습니다.",
        "username": current_user.username,
        "role": current_user.role,
        "role_name": ROLE_NAMES.get(current_user.role),
    }), 200


@app.route('/api/access/admin', methods=['GET'])
@role_required(ROLE_ADMIN)
def access_admin(current_user):
    return jsonify({
        "msg": f"{current_user.username}님, 관리자 페이지 접근이 허용되었습니다.",
        "username": current_user.username,
        "role": current_user.role,
        "role_name": ROLE_NAMES.get(current_user.role),
    }), 200


# ----------------- 요구사항 5) 관리자 페이지의 회원 조회/수정/삭제 -----------------
@app.route('/api/admin/users', methods=['GET'])
def admin_list_users():
    """사람(관리자 로그인 JWT)과 자동화(privilege_revoke_bot.py 의 X-API-Key) 양쪽이 호출한다.

    - X-API-Key 헤더가 있으면 ADMIN_API_KEY 와 비교해서 인증한다(회수봇용).
    - 없으면 기존처럼 JWT 로그인 + 관리자 등급을 확인한다(관리자 페이지 화면용).
    - ?role=general|gold|admin 으로 등급 필터링을 지원한다(회수봇이 admin만 조회).
    """
    api_key = request.headers.get('X-API-Key')
    if api_key:
        if not check_admin_api_key():
            return jsonify({"msg": "인증 실패: X-API-Key 가 올바르지 않습니다."}), 401
    else:
        verify_jwt_in_request()
        current_user = User.query.get(get_jwt_identity())
        if not current_user:
            return jsonify({"msg": "사용자를 찾을 수 없습니다."}), 404
        if current_user.role < ROLE_ADMIN:
            return jsonify({
                "msg": f"접근 권한이 없습니다. (현재 등급: {ROLE_NAMES.get(current_user.role)}[{current_user.role}], "
                       f"필요 등급: {ROLE_NAMES.get(ROLE_ADMIN)}[{ROLE_ADMIN}] 이상)",
                "current_role": current_user.role,
                "required_role": ROLE_ADMIN,
            }), 403

    query = User.query
    role_filter = request.args.get('role')
    if role_filter:
        if role_filter.lower() not in ROLE_NAME_TO_VALUE:
            return jsonify({"msg": "role 파라미터는 general/gold/admin 중 하나여야 합니다."}), 400
        query = query.filter(User.role == ROLE_NAME_TO_VALUE[role_filter.lower()])

    users = query.order_by(User.id).all()
    return jsonify({"users": [u.to_dict() for u in users]}), 200


@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@role_required(ROLE_ADMIN)
def admin_update_user(current_user, user_id):
    target = User.query.get_or_404(user_id)
    data = request.get_json(silent=True) or {}

    if 'role' in data:
        try:
            new_role = int(data['role'])
        except (TypeError, ValueError):
            return jsonify({"msg": "role 값이 올바르지 않습니다."}), 400
        if new_role not in ROLE_NAMES:
            return jsonify({"msg": "role 은 0(일반)/1(골드)/2(관리자) 중 하나여야 합니다."}), 400
        if target.id == current_user.id and new_role != ROLE_ADMIN:
            return jsonify({"msg": "본인의 관리자 등급은 스스로 낮출 수 없습니다."}), 400
        # 관리자로 새로 올릴 때만 부여자를 기록하고, 관리자가 아니게 되면 비운다.
        if new_role == ROLE_ADMIN:
            if target.role != ROLE_ADMIN:
                target.role_granted_by = current_user.username
        else:
            target.role_granted_by = None
        target.role = new_role

    if 'username' in data and data['username']:
        new_username = data['username']
        if new_username != target.username and User.query.filter_by(username=new_username).first():
            return jsonify({"msg": "이미 존재하는 아이디입니다."}), 400
        target.username = new_username

    if data.get('password'):
        target.password = generate_password_hash(data['password'])

    db.session.commit()
    return jsonify(target.to_dict()), 200


@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@role_required(ROLE_ADMIN)
def admin_delete_user(current_user, user_id):
    if user_id == current_user.id:
        return jsonify({"msg": "본인 계정은 삭제할 수 없습니다."}), 400
    target = User.query.get_or_404(user_id)
    db.session.delete(target)
    db.session.commit()
    return jsonify({"msg": f"{target.username} 계정을 삭제했습니다."}), 200


@app.route('/api/admin/grant', methods=['POST'])
def admin_grant_user():
    """등급 부여 엔드포인트 — 회수(/api/admin/revoke)의 짝.

    회수봇을 시험할 때 '허용목록 밖 관리자'를 만들어 두는 용도로 쓴다. 관리자
    페이지(PUT /api/admin/users/<id>)와 달리 사람의 로그인 없이 X-API-Key 로만
    인증하므로 Postman·스크립트에서 바로 부를 수 있다.

    role 은 'admin' 처럼 이름으로도, 2 처럼 숫자로도 받는다. 생략하면 admin.
    """
    if not check_admin_api_key():
        return jsonify({"msg": "인증 실패: X-API-Key 가 없거나 올바르지 않습니다."}), 401

    data = request.get_json(silent=True) or {}
    username = data.get('username')
    if not username:
        return jsonify({"msg": "username 은 필수입니다."}), 400

    role_raw = data.get('role', 'admin')
    if isinstance(role_raw, str) and not role_raw.strip().isdigit():
        new_role = ROLE_NAME_TO_VALUE.get(role_raw.strip().lower())
    else:
        new_role = int(role_raw)
    if new_role not in ROLE_NAMES:
        return jsonify({"msg": "role 은 general/gold/admin 또는 0/1/2 중 하나여야 합니다."}), 400

    target = User.query.filter_by(username=username).first()
    if not target:
        return jsonify({"msg": "사용자를 찾을 수 없습니다."}), 404

    old_role = target.role
    target.role = new_role
    # 관리자로 올릴 때만 부여자를 남긴다. 회수봇이 '누가 줬는지' 를 신고에 싣는다.
    target.role_granted_by = data.get('granted_by', 'api') if new_role == ROLE_ADMIN else None
    # 감사(audit): 언제·왜 이 등급이 됐는가.
    target.role_granted_at = datetime.now()
    target.role_reason = (data.get('reason') or '')[:200] or None
    db.session.commit()

    event = SecurityEvent(
        student=data.get('student', 'unknown'),
        src_ip=data.get('src_ip', '127.0.0.1'),
        decision='allow',
        severity='Medium',
        reason=data.get('reason') or f"{ROLE_NAMES[new_role]} 등급 부여: {username}",
        users=username,
        source=data.get('source', 'privilege-guard'),
        generated_at=data.get('generated_at'),
    )
    db.session.add(event)
    db.session.commit()

    return jsonify({
        "msg": f"{username} 계정에 {ROLE_NAMES[new_role]} 등급을 부여했습니다.",
        "username": username,
        "old_role": ROLE_NAMES.get(old_role),
        "new_role": ROLE_NAMES.get(new_role),
        "role_granted_by": target.role_granted_by,
        "event_id": event.id,
    }), 200


@app.route('/api/admin/revoke', methods=['POST'])
def admin_revoke_user():
    """과잉권한 자동 회수 엔드포인트.

    privilege_revoke_bot.py 가 --revoke 로 직접 부르거나, 봇이 Graylog 에 신고한
    이벤트를 받아 n8n 이 대신 호출한다. 둘 다 사람이 아니라 자동화이므로 JWT 로그인
    없이 X-API-Key 로만 인증한다. 대상 계정을 일반(0) 등급으로 강등하고, 회수 사실을
    security_events 에 남겨 /security 대시보드에서도 보이게 한다.
    """
    if not check_admin_api_key():
        return jsonify({"msg": "인증 실패: X-API-Key 가 없거나 올바르지 않습니다."}), 401

    data = request.get_json(silent=True) or {}
    username = data.get('username')
    if not username:
        return jsonify({"msg": "username 은 필수입니다."}), 400

    target = User.query.filter_by(username=username).first()
    if not target:
        return jsonify({"msg": "사용자를 찾을 수 없습니다."}), 404

    old_role = target.role
    target.role = ROLE_GENERAL
    target.role_granted_by = None
    db.session.commit()

    event = SecurityEvent(
        student=data.get('student', 'unknown'),
        src_ip=data.get('src_ip', '127.0.0.1'),
        decision='deny',
        severity='High',
        reason=data.get('reason') or f"관리자 권한 자동 회수: {username}",
    )
    db.session.add(event)
    db.session.commit()

    return jsonify({
        "msg": f"{username} 계정의 관리자 권한을 회수했습니다.",
        "username": username,
        "old_role": ROLE_NAMES.get(old_role),
        "new_role": ROLE_NAMES.get(ROLE_GENERAL),
        "event_id": event.id,
    }), 200


# ----------------- 등급별 화면 -----------------
@app.route('/gold')
def gold_page():
    return render_template('gold.html')


@app.route('/admin')
def admin_page():
    return render_template('admin.html')

# ----------------- Post Endpoints (RESTful) -----------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/posts', methods=['GET'])
def get_posts():
    limit = int(request.args.get('limit', 5))
    cursor = request.args.get('cursor', type=int)
    search = request.args.get('search', '')
    category = request.args.get('category', '전체')

    query = Post.query

    # 카테고리 필터
    if category and category != '전체':
        query = query.filter(Post.category == category)
    
    # 검색어 필터 (제목 또는 내용)
    if search:
        search_term = f"%{search}%"
        query = query.filter((Post.title.like(search_term)) | (Post.content.like(search_term)))

    # 커서 페이징 처리 (ID 내림차순 기준)
    if cursor:
        query = query.filter(Post.id < cursor)

    query = query.order_by(Post.id.desc())

    # 지정한 limit보다 1개 더 가져와서 다음 페이지 존재 여부 확인
    posts = query.limit(limit + 1).all()

    has_more = False
    next_cursor = None
    if len(posts) > limit:
        has_more = True
        posts = posts[:-1] # 초과분 제거
        next_cursor = posts[-1].id

    posts_list = []
    for post in posts:
        posts_list.append({
            'id': post.id,
            'title': post.title,
            'content': post.content,
            'category': post.category,
            'author': post.author.username if post.author else 'Unknown'
        })

    return jsonify({
        'posts': posts_list,
        'has_more': has_more,
        'next_cursor': next_cursor
    })

@app.route('/api/posts', methods=['POST'])
@jwt_required()
def create_post():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    title = data.get('title')
    content = data.get('content')
    category = data.get('category', '일반')

    if not title or not content:
        return jsonify({"msg": "제목과 내용을 모두 입력해주세요."}), 400

    new_post = Post(
        title=title,
        content=content,
        category=category,
        author_id=current_user_id
    )
    db.session.add(new_post)
    db.session.commit()

    return jsonify({"msg": "게시글이 등록되었습니다."}), 201

@app.route('/api/posts/<int:id>', methods=['PUT'])
@jwt_required()
def update_post(id):
    current_user_id = get_jwt_identity()
    post = Post.query.get_or_404(id)

    if str(post.author_id) != str(current_user_id):
        return jsonify({"msg": "수정 권한이 없습니다."}), 403

    data = request.get_json()
    post.title = data.get('title', post.title)
    post.content = data.get('content', post.content)
    post.category = data.get('category', post.category)

    db.session.commit()
    return jsonify({"msg": "게시글이 수정되었습니다."}), 200

@app.route('/api/posts/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_post(id):
    current_user_id = get_jwt_identity()
    post = Post.query.get_or_404(id)

    if str(post.author_id) != str(current_user_id):
        return jsonify({"msg": "삭제 권한이 없습니다."}), 403

    db.session.delete(post)
    db.session.commit()
    return jsonify({"msg": "게시글이 삭제되었습니다."}), 200


# ----------------- Security Events (실습과제: 경보 자동화 봇) -----------------
def _create_security_post(event):
    """심화: 거부 이벤트를 게시판 '보안' 공지글로 자동 등록한다(작성자 = 시스템 계정).

    AUTO_POST_ON_DENY=1 일 때만 불린다. 봇 계정이 없으면 무작위 비밀번호로 만들어
    두고(로그인 용도가 아니라 글쓴이 표시용) 그 계정 이름으로 글을 남긴다.
    """
    bot = User.query.filter_by(username='soarbot').first()
    if not bot:
        bot = User(username='soarbot',
                   password=generate_password_hash(os.urandom(16).hex()),
                   role=ROLE_GENERAL)
        db.session.add(bot)
        db.session.flush()

    post = Post(
        title=f'[보안][{event.student}] {event.src_ip} 접근 거부 ({event.severity})',
        content=(f'{event.reason}\n시도 계정: {event.users}\n'
                 f'마지막 시도: {event.last_seen}\n수집: {event.generated_at}'),
        category='보안', author_id=bot.id)
    db.session.add(post)
    db.session.flush()
    return post.id


@app.route('/api/security/events', methods=['POST'])
def create_security_event():
    # n8n 이 호출하는 엔드포인트. 헤더의 API 키로 인증한다 (JWT 로그인과는 별개).
    if request.headers.get('X-API-Key') != SECURITY_API_KEY:
        return jsonify({"msg": "인증 실패: X-API-Key 가 없거나 올바르지 않습니다."}), 401

    data = request.get_json(silent=True) or {}
    student = data.get('student')
    src_ip = data.get('src_ip')
    decision = data.get('decision')

    if not student or not src_ip or decision not in ('allow', 'deny'):
        return jsonify({"msg": "student, src_ip, decision(allow|deny) 은 필수입니다."}), 400

    event = SecurityEvent(
        student=student,
        src_ip=src_ip,
        decision=decision,
        severity=data.get('severity', 'Low'),
        reason=data.get('reason'),
        fail_count=int(data.get('fail_count') or 0),
        users=data.get('users'),
        last_seen=data.get('last_seen'),
        window_min=data.get('window_min'),
        source=data.get('source', 'login_guard'),
        generated_at=data.get('generated_at'),
    )
    db.session.add(event)
    db.session.flush()   # event.id 확보

    post_id = None
    if decision == 'deny' and AUTO_POST_ON_DENY:
        post_id = _create_security_post(event)

    db.session.commit()   # 이벤트 + 공지글을 한 트랜잭션으로 함께 커밋한다.

    result = event.to_dict()
    result['post_id'] = post_id
    return jsonify(result), 201


@app.route('/api/security/events', methods=['GET'])
def list_security_events():
    """조회는 키 없이(수업 확인용). ?student= / ?decision= / ?limit= 으로 거른다."""
    student = request.args.get('student')
    decision = request.args.get('decision')
    limit = request.args.get('limit', default=20, type=int)

    query = SecurityEvent.query
    if student:
        query = query.filter_by(student=student)
    if decision in ('allow', 'deny'):
        query = query.filter_by(decision=decision)

    events = query.order_by(SecurityEvent.id.desc()).limit(min(limit, 100)).all()
    return jsonify({"count": len(events), "events": [e.to_dict() for e in events]})


@app.route('/api/security/events/summary', methods=['GET'])
def security_events_summary():
    """허용/거부 건수 + 거부 실패횟수 상위 IP 5개."""
    student = request.args.get('student')

    q_decision = db.session.query(SecurityEvent.decision, db.func.count(SecurityEvent.id))
    q_top = (db.session.query(SecurityEvent.src_ip, db.func.sum(SecurityEvent.fail_count))
             .filter(SecurityEvent.decision == 'deny'))
    if student:
        q_decision = q_decision.filter(SecurityEvent.student == student)
        q_top = q_top.filter(SecurityEvent.student == student)

    by_decision = dict(q_decision.group_by(SecurityEvent.decision).all())
    top = (q_top.group_by(SecurityEvent.src_ip)
           .order_by(db.func.sum(SecurityEvent.fail_count).desc()).limit(5).all())

    return jsonify({
        "student": student,
        "by_decision": by_decision,
        "top_deny_ips": [{"src_ip": ip, "fails": int(n or 0)} for ip, n in top],
    })


@app.route('/api/security/students', methods=['GET'])
def list_security_students():
    """대시보드 드롭다운용 — 기록이 있는 학생 목록."""
    rows = (db.session.query(SecurityEvent.student)
            .distinct().order_by(SecurityEvent.student).all())
    return jsonify({"students": [r[0] for r in rows]})


@app.route('/security')
def security_dashboard():
    # 보안 이벤트 대시보드 화면 (데이터는 위의 GET /api/security/events 로 가져간다)
    return render_template('security.html')


# ----------------- 공공 데이터 연동 설정 (부산테마여행) -----------------

import os
from urllib.parse import unquote
from dotenv import load_dotenv

load_dotenv()   # 같은 폴더의 .env 를 읽어 환경변수로 올려 준다 (이 한 줄이 핵심)

PUBLIC_API_KEY = os.environ.get("PUBLIC_API_KEY")

# 공공데이터포털은 Encoding 키와 Decoding 키 두 가지를 발급한다.
# requests 가 params 를 다시 URL 인코딩하므로, Encoding 키를 그대로 넘기면
# %2B -> %252B 처럼 이중 인코딩되어 SERVICE KEY IS NOT REGISTERED ERROR 가 난다.
# 여기서 한 번 풀어두면 어느 쪽 키를 넣어도 정상 동작한다.
if PUBLIC_API_KEY:
    PUBLIC_API_KEY = unquote(PUBLIC_API_KEY)

# 키 값 자체는 절대 출력하지 않는다
if PUBLIC_API_KEY:
    print("키 로드됨 — 앞 4자리:", PUBLIC_API_KEY[:4] + "****")
else:
    print("키 없음 — 더미 실습 진행")


PUBLIC_API_URL = "http://apis.data.go.kr/6260000/RecommendedService/getRecommendedKr"

@app.route('/api/public/posts', methods=['GET'])
def get_public_posts():
    params = {
        'serviceKey': PUBLIC_API_KEY,
        'numOfRows': '100',
        'pageNo': '1',
        'resultType': 'json'
    }
    try:
        response = requests.get(PUBLIC_API_URL, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            return jsonify({"msg": "공공 API 호출 실패", "status": response.status_code}), 500
    except Exception as e:
        return jsonify({"msg": "서버 통신 에러 발생", "error": str(e)}), 500

@app.route('/public-posts')
def public_posts_page():
    return render_template('public_posts.html')

@app.route('/public-posts/<int:uc_seq>')
def public_post_detail_page(uc_seq):
    return render_template('public_detail.html', uc_seq=uc_seq)


# ----------------- 앱 실행 -----------------
if __name__ == '__main__':
    # 기본값은 127.0.0.1 — 이 PC 안에서만 접속된다.
    # 리눅스 VM 등 같은 네트워크의 다른 장비에서 붙어야 하면 .env 에
    # FLASK_HOST=0.0.0.0 을 넣는다. 단, debug=True 인 채로 밖에 열면
    # Werkzeug 디버거가 노출돼 원격 코드 실행이 가능해지므로
    # 외부에 열 때는 FLASK_DEBUG=0 도 같이 넣어 디버거를 끈다.
    app.run(
        host=os.environ.get("FLASK_HOST", "127.0.0.1"),
        debug=os.environ.get("FLASK_DEBUG", "1") == "1",
        port=5000,
    )