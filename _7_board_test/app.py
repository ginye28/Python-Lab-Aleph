from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime
import os
import time
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
# RBAC: 과잉권한 허용목록(콤마 구분 사용자명). 이 목록 밖의 admin 은 회수 대상.
ADMIN_ALLOWLIST = set(
    u.strip() for u in os.environ.get("ADMIN_ALLOWLIST", "").split(",") if u.strip()
)

db = SQLAlchemy(app)
jwt = JWTManager(app)

# ----------------- Database Models -----------------
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='user')  # user | admin
    role_granted_by = db.Column(db.String(80))
    role_granted_at = db.Column(db.DateTime)
    role_reason = db.Column(db.String(200))

    def to_dict(self):
        return {
            "id": self.id, "username": self.username, "role": self.role,
            "role_granted_by": self.role_granted_by,
            "role_granted_at": self.role_granted_at.isoformat() if self.role_granted_at else None,
            "role_reason": self.role_reason,
        }

class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False, default='일반')
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    author = db.relationship('User', backref=db.backref('posts', lazy=True))

class SecurityEvent(db.Model):
    __tablename__ = 'security_events'
    id = db.Column(db.Integer, primary_key=True)
    student = db.Column(db.String(80), nullable=False)
    src_ip = db.Column(db.String(45), nullable=False)
    decision = db.Column(db.String(10), nullable=False)   # 'allow' | 'deny'
    severity = db.Column(db.String(10))                   # 'Low' | 'Medium' | 'High'
    reason = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "student": self.student,
            "src_ip": self.src_ip,
            "decision": self.decision,
            "severity": self.severity,
            "reason": self.reason,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

class BlockedIP(db.Model):
    # 112: 실차단(active response) 차단목록. 미들웨어가 매 요청 이 표를 보고 403.
    __tablename__ = 'blocked_ips'
    ip = db.Column(db.String(45), primary_key=True)
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

_SEV_RANK = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}


class Incident(db.Model):
    # 114: 흩어진 security_events 를 src_ip 기준 하나의 인시던트 티켓으로 취합.
    __tablename__ = 'incidents'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    src_ip = db.Column(db.String(45), index=True)
    severity = db.Column(db.String(10), default='Medium')
    status = db.Column(db.String(12), default='open', index=True)
    summary = db.Column(db.Text)
    event_count = db.Column(db.Integer, default=0)
    actions = db.Column(db.String(255))
    student = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    closed_at = db.Column(db.DateTime)

    def to_dict(self):
        return {
            "id": self.id, "title": self.title, "src_ip": self.src_ip,
            "severity": self.severity, "status": self.status, "summary": self.summary,
            "event_count": self.event_count, "actions": self.actions, "student": self.student,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
        }


def _ensure_schema():
    # RBAC: db.create_all() 은 이미 있는 users 표에 컬럼을 추가하지 못한다.
    # 없는 컬럼만 골라 ALTER — 여러 번 켜도 안전하다.
    from sqlalchemy import text, inspect
    insp = inspect(db.engine)
    cols = {c["name"] for c in insp.get_columns("users")}
    stmts = []
    if "role" not in cols:
        stmts.append("ALTER TABLE users ADD COLUMN role VARCHAR(10) NOT NULL DEFAULT 'user'")
    if "role_granted_by" not in cols:
        stmts.append("ALTER TABLE users ADD COLUMN role_granted_by VARCHAR(80)")
    if "role_granted_at" not in cols:
        stmts.append("ALTER TABLE users ADD COLUMN role_granted_at DATETIME")
    if "role_reason" not in cols:
        stmts.append("ALTER TABLE users ADD COLUMN role_reason VARCHAR(200)")
    with db.engine.begin() as conn:
        for s in stmts:
            conn.execute(text(s))
    if stmts:
        print(f"[RBAC] users 표 컬럼 {len(stmts)}개 추가함", flush=True)


with app.app_context():
    db.create_all()
    _ensure_schema()


def _client_ip():
    # 112: 프록시(n8n 등) 뒤면 X-Forwarded-For 첫 홉, 아니면 remote_addr.
    xff = request.headers.get('X-Forwarded-For', '')
    return xff.split(',')[0].strip() if xff else (request.remote_addr or '')


@app.before_request
def _block_ip_guard():
    # 관리자 API 는 예외 — 자기 차단으로 복구 불능 방지
    if request.path.startswith('/api/admin'):
        return None
    ip = _client_ip()
    if ip and db.session.get(BlockedIP, ip):
        return jsonify({"msg": "차단된 IP 입니다(관리자에게 문의).", "ip": ip, "blocked": True}), 403
    return None


@app.after_request
def _web_scan_probe(response):
    # 공격②: 스캐너(nikto·gobuster 등)는 없는 경로에 404 를 대량 유발 → GELF(rule='web-scan') 로 신고.
    try:
        if response.status_code == 404 and not request.path.startswith('/api/admin'):
            import json as _json, socket as _socket
            msg = {
                "version": "1.1", "host": "board", "short_message": f"404 probe {request.path[:80]}",
                "level": 5, "_rule": "web-scan", "_src_ip": _client_ip(), "_path": request.path[:120],
            }
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            s.sendto(_json.dumps(msg).encode(), ("localhost", 12201))
            s.close()
    except Exception:
        pass
    return response


def _admin_authorized():
    return request.headers.get('X-API-Key') == SECURITY_API_KEY


@app.route('/api/admin/block', methods=['POST'])
def admin_block_ip():
    if not _admin_authorized():
        return jsonify({"msg": "인증 실패"}), 401
    data = request.get_json(silent=True) or {}
    ip = (data.get('ip') or data.get('src_ip') or '').strip()
    if not ip:
        return jsonify({"msg": "ip(또는 src_ip) 는 필수입니다."}), 400
    actor = data.get('student') or 'n8n'
    existing = db.session.get(BlockedIP, ip)
    if existing:
        return jsonify({"msg": "이미 차단된 IP", "ip": ip, "blocked": True, "changed": False}), 200
    db.session.add(BlockedIP(ip=ip, reason=(data.get('reason') or f'자동 차단 by {actor}')[:200], blocked_by=actor))
    ev = SecurityEvent(
        student=(data.get('student') or actor)[:50], src_ip=ip,
        decision='deny', severity=data.get('severity', 'High'),
        reason=(data.get('reason') or f'IP 실차단: {ip}')[:255],
    )
    db.session.add(ev)
    db.session.commit()
    return jsonify({"msg": "IP 차단 완료", "ip": ip, "blocked": True, "changed": True, "event_id": ev.id}), 200


@app.route('/api/admin/unblock', methods=['POST'])
def admin_unblock_ip():
    if not _admin_authorized():
        return jsonify({"msg": "인증 실패"}), 401
    data = request.get_json(silent=True) or {}
    ip = (data.get('ip') or '').strip()
    existing = db.session.get(BlockedIP, ip) if ip else None
    if existing:
        db.session.delete(existing)
        db.session.commit()
    return jsonify({"msg": "해제 완료", "ip": ip, "blocked": False}), 200


@app.route('/api/admin/blocked', methods=['GET'])
def admin_list_blocked():
    if not _admin_authorized():
        return jsonify({"msg": "인증 실패"}), 401
    rows = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).all()
    return jsonify([r.to_dict() for r in rows])


def _build_incident_summary(src_ip, events):
    by_source, actions, worst, lines = {}, set(), 'Low', []
    for e in events:
        src = getattr(e, 'source', None) or 'security_events'
        by_source[src] = by_source.get(src, 0) + 1
        if e.decision:
            actions.add(e.decision)
        if _SEV_RANK.get(e.severity, 1) > _SEV_RANK.get(worst, 1):
            worst = e.severity
        when = e.created_at.strftime('%Y-%m-%d %H:%M:%S') if e.created_at else '?'
        lines.append(f"- {when} [{e.severity}] {e.reason or ''}")
    summary = (
        f"[인시던트 요약] 출발지 {src_ip}\n"
        f"- 관련 이벤트: {len(events)}건 ({', '.join(f'{k}×{v}' for k, v in sorted(by_source.items())) or '없음'})\n"
        f"- 취해진 조치: {', '.join(sorted(actions)) or '없음'}\n"
        f"- 최고 심각도: {worst}\n[타임라인]\n" + "\n".join(lines[:20])
    )
    return summary, worst, (', '.join(sorted(actions)) or '없음'), len(events)


@app.route('/api/admin/incident', methods=['POST'])
def admin_create_incident():
    # 114: security_events 를 src_ip 기준으로 취합해 티켓 1개(open)로 유지.
    if not _admin_authorized():
        return jsonify({"msg": "인증 실패"}), 401
    data = request.get_json(silent=True) or {}
    src_ip = (data.get('src_ip') or data.get('ip') or '').strip()
    if not src_ip:
        return jsonify({"msg": "src_ip 는 필수입니다."}), 400

    since = datetime.now() - timedelta(hours=int(data.get('hours') or 24))
    last_closed = (Incident.query.filter_by(src_ip=src_ip, status='closed')
                   .filter(Incident.closed_at.isnot(None))
                   .order_by(Incident.closed_at.desc()).first())
    if last_closed and last_closed.closed_at > since:
        since = last_closed.closed_at

    events = (SecurityEvent.query.filter(SecurityEvent.src_ip == src_ip, SecurityEvent.created_at >= since)
              .order_by(SecurityEvent.created_at.desc()).all())
    summary, worst, actions, cnt = _build_incident_summary(src_ip, events)

    inc = Incident.query.filter_by(src_ip=src_ip, status='open').first()
    created = False
    if not inc:
        inc = Incident(src_ip=src_ip, status='open')
        db.session.add(inc)
        created = True

    inc.title = (data.get('title') or f'보안 인시던트: {src_ip} ({cnt}건)')[:200]
    inc.severity = max([data.get('severity') or worst, worst, inc.severity or 'Low'], key=lambda s: _SEV_RANK.get(s, 0))
    inc.summary, inc.event_count, inc.actions = summary, cnt, actions[:255]
    inc.student = (data.get('student') or 'unknown')[:50]
    db.session.commit()

    return jsonify({
        "msg": "인시던트 생성" if created else "인시던트 갱신",
        "created": created, "incident": inc.to_dict(),
    }), (201 if created else 200)


@app.route('/api/admin/incidents', methods=['GET'])
def admin_list_incidents():
    if not _admin_authorized():
        return jsonify({"msg": "인증 실패"}), 401
    status = request.args.get('status')
    query = Incident.query
    if status:
        query = query.filter_by(status=status)
    rows = query.order_by(Incident.updated_at.desc()).all()
    return jsonify([r.to_dict() for r in rows])


@app.route('/api/admin/incident/close', methods=['POST'])
def admin_close_incident():
    if not _admin_authorized():
        return jsonify({"msg": "인증 실패"}), 401
    data = request.get_json(silent=True) or {}
    inc = db.session.get(Incident, data.get('id')) if data.get('id') else None
    if not inc:
        return jsonify({"msg": "티켓을 찾을 수 없습니다."}), 404
    inc.status = 'closed'
    inc.closed_at = datetime.now()
    db.session.commit()
    return jsonify({"msg": "티켓 종료", "incident": inc.to_dict()}), 200


# ----------------- RBAC: 과잉권한 탐지·회수 -----------------
@app.route('/api/admin/users', methods=['GET'])
def admin_list_users():
    if not _admin_authorized():
        return jsonify({"msg": "인증 실패"}), 401
    role = request.args.get('role')
    query = User.query
    if role:
        query = query.filter_by(role=role)
    return jsonify([u.to_dict() for u in query.order_by(User.id).all()])


@app.route('/api/admin/violations', methods=['GET'])
def admin_violations():
    # 허용목록(ADMIN_ALLOWLIST) 밖의 admin = 과잉권한.
    if not _admin_authorized():
        return jsonify({"msg": "인증 실패"}), 401
    admins = User.query.filter_by(role='admin').all()
    violations = [u.to_dict() for u in admins if u.username not in ADMIN_ALLOWLIST]
    return jsonify(violations)


@app.route('/api/admin/grant', methods=['POST'])
def admin_grant():
    if not _admin_authorized():
        return jsonify({"msg": "인증 실패"}), 401
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    role = (data.get('role') or 'user').strip()
    if not username or role not in ('user', 'admin'):
        return jsonify({"msg": "username, role(user|admin) 은 필수입니다."}), 400
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"msg": "사용자를 찾을 수 없습니다."}), 404
    old_role = user.role
    user.role = role
    user.role_granted_by = data.get('granted_by') or 'apikey'
    user.role_granted_at = datetime.now()
    user.role_reason = (data.get('reason') or '')[:200]
    db.session.commit()
    return jsonify({"msg": "권한 변경 완료", "username": username, "old_role": old_role, "new_role": role}), 200


@app.route('/api/admin/revoke', methods=['POST'])
def admin_revoke():
    # 과잉권한 회수: admin -> user. 이미 user 면 멱등(변경 없이 200).
    if not _admin_authorized():
        return jsonify({"msg": "인증 실패"}), 401
    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    if not username:
        return jsonify({"msg": "username 은 필수입니다."}), 400
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"msg": "사용자를 찾을 수 없습니다."}), 404

    old_role = user.role
    if old_role != 'admin':
        return jsonify({"msg": "이미 admin 이 아닙니다(멱등)", "username": username,
                         "old_role": old_role, "new_role": old_role, "changed": False}), 200

    user.role = 'user'
    user.role_granted_by = 'privilege-guard'
    user.role_granted_at = datetime.now()
    user.role_reason = (data.get('reason') or '과잉권한 자동 회수')[:200]
    db.session.add(user)

    ev = SecurityEvent(
        student=(data.get('student') or 'privilege-guard')[:50],
        src_ip=data.get('src_ip') or '0.0.0.0',
        decision='deny', severity=data.get('severity', 'High'),
        reason=f"과잉권한 자동 회수: {username} (admin→user)"[:255],
    )
    db.session.add(ev)
    db.session.commit()
    return jsonify({"msg": "권한 회수 완료", "username": username, "old_role": old_role,
                     "new_role": "user", "changed": True, "event_id": ev.id}), 200


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
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "회원가입이 완료되었습니다."}), 201

_SECURITY_LOG_PATH = os.path.join(os.path.dirname(__file__), "logs", "security.log")


def _send_login_fail_gelf(username, src_ip):
    # 111: 로그인 실패를 GELF 로 Graylog 에 신고 (브루트포스·스프레이·IP차단 탐지의 전제)
    import json as _json, socket as _socket
    msg = {
        "version": "1.1", "host": "board", "short_message": f"login failed: {username}",
        "level": 5, "_rule": "login-bruteforce", "_username": username, "_src_ip": src_ip,
    }
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.sendto(_json.dumps(msg).encode(), ("localhost", 12201))
        s.close()
    except OSError:
        pass  # Graylog 가 꺼져 있어도 로그인 자체는 계속 동작해야 한다

    # 129: 같은 사건을 파일로도 남긴다 — Wazuh 에이전트가 이 파일을 읽는다.
    # 포맷은 실제 랩에서 검증된 syslog 태그 형식: "Mon  D HH:MM:SS <host> board: login_failed user=... src_ip=..."
    # (Wazuh 의 syslog 전처리가 날짜/호스트/태그를 먼저 떼어내므로, 이 형식이어야 webapp-login 디코더가 매치한다)
    try:
        os.makedirs(os.path.dirname(_SECURITY_LOG_PATH), exist_ok=True)
        line = time.strftime("%b %e %H:%M:%S") + f" board board: login_failed user={username} src_ip={src_ip}\n"
        with open(_SECURITY_LOG_PATH, "a") as f:
            f.write(line)
    except OSError:
        pass


@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        _send_login_fail_gelf(username or '(unknown)', _client_ip())
        return jsonify({"msg": "아이디 또는 비밀번호가 올바르지 않습니다."}), 401

    access_token = create_access_token(identity=str(user.id))
    return jsonify({
        "access_token": access_token,
        "username": user.username
    }), 200

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
@app.route('/api/security/events', methods=['POST'])
def create_security_event():
    # n8n 이 호출하는 엔드포인트. 헤더의 API 키로 인증한다 (JWT 로그인과는 별개).
    if request.headers.get('X-API-Key') != SECURITY_API_KEY:
        return jsonify({"msg": "인증 실패: X-API-Key 가 없거나 올바르지 않습니다."}), 401

    data = request.get_json(silent=True) or {}
    student = data.get('student')
    src_ip = data.get('src_ip')
    decision = data.get('decision')

    if not student or not src_ip or not decision:
        return jsonify({"msg": "student, src_ip, decision 은 필수입니다."}), 400

    event = SecurityEvent(
        student=student,
        src_ip=src_ip,
        decision=decision,
        severity=data.get('severity'),
        reason=data.get('reason'),
    )
    db.session.add(event)
    db.session.commit()

    return jsonify(event.to_dict()), 201


@app.route('/api/security/events', methods=['GET'])
def list_security_events():
    # 인증 없이 본인 기록만 조회 (student 파라미터 기준)
    student = request.args.get('student')
    query = SecurityEvent.query
    if student:
        query = query.filter_by(student=student)
    events = query.order_by(SecurityEvent.created_at.desc()).all()
    return jsonify([e.to_dict() for e in events])


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
    app.run(debug=True, port=5000)