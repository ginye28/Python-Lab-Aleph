from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
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

db = SQLAlchemy(app)
jwt = JWTManager(app)

# ----------------- Database Models -----------------
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

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

with app.app_context():
    db.create_all()

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

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
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