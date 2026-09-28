"""골드 등급 전용 API.

화면에서 메뉴를 숨기는 것만으로는 막은 게 아니다 — 주소창에 API 를 직접 쳐 보면
그대로 열린다. 그래서 서버에서 한 번 더 등급을 검사한다(@role_required(ROLE_GOLD))."""
from flask import Blueprint, jsonify

from models import Post

from .gelf import send_gelf
from .rbac import client_ip, role_required
from models.user import ROLE_GOLD, ROLE_KEYS

gold_bp = Blueprint('gold', __name__, url_prefix='/api/gold')

# 골드 전용 게시글 카테고리 (/api/gold/posts 가 이 값으로 거른다)
GOLD_CATEGORY = '골드'


@gold_bp.route('/posts', methods=['GET'])
@role_required(ROLE_GOLD)
def gold_posts(current_user):
    """골드 전용 게시글 목록.

    화면에서 메뉴를 숨기는 것만으로는 막은 게 아니다 — 주소창에 API 를 직접 쳐 보면
    그대로 열린다. 그래서 서버에서 한 번 더 등급을 검사한다."""
    # S9 상관 탐지용 — "권한을 올린 뒤 실제로 열람했는가"를 이으려면 열람 사실이 남아야
    # 한다. 남기는 값은 계정명·등급·출발지뿐(본문은 남기지 않는다 — 로그는 더 넓게 공유된다).
    try:
        send_gelf(f"gold area accessed by '{current_user.username}'", rule='gold-access',
                  username=current_user.username, role=ROLE_KEYS.get(current_user.role, ''),
                  src_ip=client_ip())
    except Exception:
        pass

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

