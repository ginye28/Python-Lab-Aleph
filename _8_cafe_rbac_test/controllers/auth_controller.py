"""회원가입 / 로그인 / 내 정보."""
from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required
from werkzeug.security import check_password_hash, generate_password_hash

from extensions import db
from models import User
from models.user import ROLE_GENERAL, ROLE_LABELS

from .gelf import send_gelf
from .rbac import client_ip

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"msg": "아이디와 비밀번호를 입력해주세요."}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "이미 존재하는 아이디입니다."}), 400

    hashed_password = generate_password_hash(password)
    # 회원가입은 항상 '일반' 등급으로만 생성한다. (등급 상승은 관리자 페이지에서만 가능)
    new_user = User(username=username, password=hashed_password, role=ROLE_GENERAL)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "회원가입이 완료되었습니다."}), 201


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password or ''):
        # 인증 실패 → Graylog 로 신고. 집계(5회)·차단은 Graylog 이벤트 → n8n → /api/admin/block 이 맡는다.
        src_ip = client_ip() or '0.0.0.0'
        send_gelf(f"failed login for '{username}' from {src_ip}",
                  rule='login-bruteforce', username=username or '(unknown)',
                  src_ip=src_ip, count=1)
        return jsonify({"msg": "아이디 또는 비밀번호가 올바르지 않습니다."}), 401

    access_token = create_access_token(identity=str(user.id))
    return jsonify({
        "access_token": access_token,
        "username": user.username,
        "role": user.role,
        "role_label": ROLE_LABELS.get(user.role),
    }), 200


@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def me():
    """현재 로그인한 사용자의 최신 등급을 DB에서 다시 조회해 돌려준다.
    (등급이 바뀐 뒤에도 재로그인 없이 최신 권한을 확인할 수 있도록 하기 위함)"""
    user = db.session.get(User, int(get_jwt_identity()))
    if not user:
        return jsonify({"msg": "사용자를 찾을 수 없습니다."}), 404
    return jsonify(user.to_dict()), 200
