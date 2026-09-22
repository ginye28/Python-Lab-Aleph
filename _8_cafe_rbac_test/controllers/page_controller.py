"""화면(HTML) 라우트만 모음. 데이터는 각 페이지의 JS 가 API 로 가져온다."""
from flask import Blueprint, render_template

page_bp = Blueprint('page', __name__)


@page_bp.route('/')
def index():
    return render_template('index.html')


@page_bp.route('/dashboard')
def security_dashboard_page():
    """보안 이벤트 대시보드 (n8n 이 저장한 허용/거부 기록)."""
    return render_template('dashboard.html')


# ----------------- 등급별 화면 (과제: 접근 제어 테스트) -----------------
# 이 프로젝트는 로그인 상태를 localStorage 의 JWT 로 관리하므로(쿠키 미사용),
# 서버는 페이지 자체는 누구에게나 내려주고, 페이지 안의 JS 가 /api/auth/me 를
# Authorization: Bearer <token> 헤더로 호출해 실제 등급을 확인한 뒤
# 화면에 콘텐츠 또는 "접근 권한 없음" 예외 화면을 그린다.
# ★ 실질적인 접근 제어(진짜 보안)는 /api/gold/... , /api/admin/... 의
#   role_required / admin_required 데코레이터가 서버 쪽에서 강제한다.
#   페이지의 JS 체크는 사용자 경험(화면 분기)일 뿐이다.
@page_bp.route('/gold')
def gold_page():
    return render_template('gold.html')


@page_bp.route('/admin')
def admin_page():
    return render_template('admin.html')


@page_bp.route('/public-posts')
def public_posts_page():
    return render_template('public_posts.html')


@page_bp.route('/public-posts/<int:uc_seq>')
def public_post_detail_page(uc_seq):
    return render_template('public_detail.html', uc_seq=uc_seq)
