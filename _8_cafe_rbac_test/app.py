from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity,
    verify_jwt_in_request,
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from functools import wraps
import os
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
ROLE_NAME_TO_VALUE = {'general': ROLE_GENERAL, 'gold': ROLE_GOLD, 'admin': ROLE_ADMIN}

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

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "role_name": ROLE_NAMES.get(self.role, '알수없음'),
            "role_granted_by": self.role_granted_by,
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

def ensure_role_granted_by_column():
    """이미 만들어져 있는 cafe_users 에 role_granted_by 컬럼을 채워 넣는다.

    db.create_all() 은 '없는 테이블'만 만들고 기존 테이블에 컬럼을 추가하지는 않는다.
    이 실습은 마이그레이션 도구(alembic)를 쓰지 않으므로, 예전 스키마로 만들어진
    테이블을 쓰던 사람도 앱만 다시 켜면 되도록 여기서 한 번 확인하고 붙인다.
    컬럼이 이미 있으면 아무 것도 하지 않는다.
    """
    columns = {c['name'] for c in db.inspect(db.engine).get_columns('cafe_users')}
    if 'role_granted_by' in columns:
        return
    db.session.execute(db.text('ALTER TABLE cafe_users ADD COLUMN role_granted_by VARCHAR(80) NULL'))
    db.session.commit()
    print('[마이그레이션] cafe_users 에 role_granted_by 컬럼을 추가했습니다.')


with app.app_context():
    db.create_all()
    ensure_role_granted_by_column()

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
    if not user or not check_password_hash(user.password, password):
        return jsonify({"msg": "아이디 또는 비밀번호가 올바르지 않습니다."}), 401

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
    db.session.commit()

    event = SecurityEvent(
        student=data.get('student', 'unknown'),
        src_ip=data.get('src_ip', '127.0.0.1'),
        decision='allow',
        severity='Medium',
        reason=data.get('reason') or f"{ROLE_NAMES[new_role]} 등급 부여: {username}",
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