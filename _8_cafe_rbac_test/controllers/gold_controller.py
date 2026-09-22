"""골드 등급 전용 API.

실질적인 골드 등급 강제는 여기서 서버가 한다 (문서 4-6 핵심 교훈:
"화면에서 메뉴를 숨기는 건 보안이 아니다" — /gold 링크만 숨겨도 이 API 를 직접
두드리면 role_required 가 gold 미만은 403, 미로그인은 401 로 그대로 차단한다).
"""
from flask import Blueprint, jsonify

from models.user import ROLE_GOLD

from .rbac import role_required

gold_bp = Blueprint('gold', __name__, url_prefix='/api/gold')


@gold_bp.route('/posts', methods=['GET'])
@role_required(ROLE_GOLD)
def gold_posts():
    return jsonify({"notices": [
        "📌 중간 관리자 공지: 이번 주 게시판 신고 내역을 확인해주세요.",
        "📌 골드 등급 전용 안내: 우수 회원 이벤트가 곧 오픈됩니다.",
        "📌 관리자 페이지 접근은 여전히 관리자 등급만 가능합니다.",
    ]}), 200
