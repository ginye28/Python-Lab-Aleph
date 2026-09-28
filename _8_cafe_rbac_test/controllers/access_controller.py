"""등급별 접근 확인용 엔드포인트 — 프런트가 '접근 허용/거부' 화면 분기를 확인할 때 쓴다."""
from flask import Blueprint, jsonify

from models.user import ROLE_ADMIN, ROLE_GOLD, ROLE_NAMES

from .rbac import role_required

access_bp = Blueprint('access', __name__, url_prefix='/api/access')


@access_bp.route('/gold', methods=['GET'])
@role_required(ROLE_GOLD)
def access_gold(current_user):
    return jsonify({
        "msg": f"{current_user.username}님, 골드 라운지 접근이 허용되었습니다.",
        "username": current_user.username,
        "role": current_user.role,
        "role_name": ROLE_NAMES.get(current_user.role),
    }), 200


@access_bp.route('/admin', methods=['GET'])
@role_required(ROLE_ADMIN)
def access_admin(current_user):
    return jsonify({
        "msg": f"{current_user.username}님, 관리자 페이지 접근이 허용되었습니다.",
        "username": current_user.username,
        "role": current_user.role,
        "role_name": ROLE_NAMES.get(current_user.role),
    }), 200
