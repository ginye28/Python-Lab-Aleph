"""인증(authentication)/인가(authorization) 공용 헬퍼 — 한 곳에서만 판정한다.

  401 = 네가 누구인지 모른다(로그인 안 함/키 없음)
  403 = 누구인지는 알지만 등급이 모자라다
"""
from functools import wraps

from flask import current_app, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required, verify_jwt_in_request

from models import User
from models.user import ROLE_ADMIN, ROLE_NAMES


def client_ip():
    """요청의 실제 클라이언트 IP. 프록시(n8n 등) 뒤라면 X-Forwarded-For 첫 홉을 신뢰한다.
    (실습 한정 규칙 — 실서비스는 신뢰 프록시 목록으로 검증해야 스푸핑을 막는다.)"""
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr or ''


def check_admin_api_key():
    """X-API-Key 헤더를 ADMIN_API_KEY 와 비교한다."""
    return request.headers.get('X-API-Key') == current_app.config.get('ADMIN_API_KEY')


def is_trusted_automation():
    """유효한 API 키(보안/관리자)를 제시한 요청인가 — SOAR 봇 판별용.

    키가 설정돼 있지 않으면(빈 값) 어떤 요청도 신뢰하지 않는다(fail-closed)."""
    key = request.headers.get('X-API-Key', '')
    if not key:
        return False
    valid = {current_app.config.get('SECURITY_API_KEY') or '',
             current_app.config.get('ADMIN_API_KEY') or ''} - {''}
    return key in valid


def role_required(min_role):
    """접근에 필요한 최소 등급을 지정하는 데코레이터.

    등급이 모자라면 403 과 함께 '현재 등급 / 필요 등급' 을 그대로 돌려준다.
    프런트에서는 이 정보를 그대로 화면에 예외 메시지로 출력한다.
    통과하면 현재 사용자(User)를 함수의 첫 인자로 넘겨준다."""
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


def require_admin():
    """관리자 전용 엔드포인트 공통 인증(함수 호출형 — 데코레이터가 아니다).

    ① X-API-Key 헤더가 ADMIN_API_KEY 와 일치하면 통과(자동화 봇용) — 이때는 (None, None) 반환.
    ② 없으면 JWT 로그인 + 관리자(2) 등급을 확인한다 — 통과하면 (User, None) 반환.
    실패하면 (None, (jsonify(...), status)) 형태로 바로 돌려줄 응답을 반환한다."""
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
