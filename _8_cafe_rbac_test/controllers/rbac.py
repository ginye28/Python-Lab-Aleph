"""인가(Authorization) 공용 데코레이터 — 한 곳에서만 판정한다.

인증(authentication) 과 인가(authorization) 는 다른 문제라 응답 코드도 다르다.
  401 = 네가 누구인지 모른다(로그인 안 함)
  403 = 누구인지는 알지만 등급이 모자라다
"""
import hmac
from functools import wraps

from flask import current_app, g, jsonify, request
from flask_jwt_extended import (
    get_jwt_identity, jwt_required, verify_jwt_in_request,
)

from extensions import db
from models import User
from models.user import ROLE_ADMIN, ROLE_LABELS


def client_ip():
    """요청의 실제 클라이언트 IP. 프록시(n8n·nginx) 뒤면 X-Forwarded-For 첫 홉을 신뢰.
    (랩 한정 규칙 — 실서비스는 신뢰 프록시 목록으로 검증해야 스푸핑을 막는다.)"""
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr or ''


def role_required(min_role):
    """로그인 + 최소 등급(min_role) 이상만 통과시킨다. (인증 실패 401, 인가 실패 403)"""
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            user = db.session.get(User, int(get_jwt_identity()))
            if not user:
                return jsonify({"msg": "사용자를 찾을 수 없습니다."}), 404
            if user.role < min_role:
                return jsonify({
                    "msg": "해당 등급의 접근 권한이 없습니다.",
                    "required_role": min_role,
                    "required_role_label": ROLE_LABELS.get(min_role),
                    "your_role": user.role,
                    "your_role_label": ROLE_LABELS.get(user.role),
                }), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def _valid_admin_api_key():
    """관리자 API에 기계(봇/n8n)가 X-API-Key 로 접근할 때의 검사."""
    expected = current_app.config.get("ADMIN_API_KEY")
    if not expected:
        return False
    sent = request.headers.get("X-API-Key")
    return bool(sent) and hmac.compare_digest(sent, expected)


def admin_required(fn):
    """관리자 API 접근 제어. 기계는 X-API-Key, 사람은 JWT + role=admin (문서 4-2)."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if _valid_admin_api_key():
            g.admin_actor = "apikey"
            return fn(*args, **kwargs)

        verify_jwt_in_request()  # 토큰 없음/무효면 여기서 401 로 응답됨
        user = db.session.get(User, int(get_jwt_identity()))
        if not user:
            return jsonify({"msg": "사용자를 찾을 수 없습니다."}), 404
        if user.role < ROLE_ADMIN:
            return jsonify({
                "msg": "해당 등급의 접근 권한이 없습니다.",
                "required_role": ROLE_ADMIN,
                "required_role_label": ROLE_LABELS.get(ROLE_ADMIN),
                "your_role": user.role,
                "your_role_label": ROLE_LABELS.get(user.role),
            }), 403
        g.admin_actor = user.username
        return fn(*args, **kwargs)
    return wrapper
