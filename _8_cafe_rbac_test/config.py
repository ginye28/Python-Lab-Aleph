"""설정 한 곳에 모으기.

비밀값(DB 비밀번호·JWT 키·API 키)은 코드에 쓰지 않고 같은 폴더의 .env 에서 읽는다.
.env 는 절대 깃에 올리지 않는다(.gitignore). 제출·공유용으로는 .env.example 만 남긴다.
"""
import os
from datetime import timedelta
from urllib.parse import unquote

from dotenv import load_dotenv

load_dotenv()   # 같은 폴더의 .env → 환경변수 (import 시점 1회)

# ── DB 접속 정보 ──────────────────────────────────────
# host 는 127.0.0.1 로 고정한다. Windows 에서 localhost 는 IPv6(::1) 로 먼저
# 해석돼 도커 포트포워딩과 어긋나는 경우가 있다.
_DB_USER = os.environ.get('MYSQL_USER', 'root')
_DB_PASSWORD = os.environ.get('MYSQL_ROOT_PASSWORD', '')   # 기본값 없음 - .env 에서만 읽는다
_DB_HOST = os.environ.get('MYSQL_HOST', '127.0.0.1')
_DB_PORT = os.environ.get('MYSQL_PORT', '3306')
_DB_NAME = os.environ.get('MYSQL_DATABASE', 'github_db')

# 공공데이터포털은 Encoding 키와 Decoding 키 두 가지를 발급한다. requests 가 params 를
# 다시 URL 인코딩하므로, Encoding 키를 그대로 넘기면 %2B -> %252B 처럼 이중 인코딩되어
# SERVICE KEY IS NOT REGISTERED ERROR 가 난다. 여기서 한 번 풀어두면 어느 쪽 키를 넣어도 된다.
_PUBLIC_API_KEY = os.environ.get('PUBLIC_API_KEY')
if _PUBLIC_API_KEY:
    _PUBLIC_API_KEY = unquote(_PUBLIC_API_KEY)


class Config:
    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{_DB_USER}:{_DB_PASSWORD}@{_DB_HOST}:{_DB_PORT}/{_DB_NAME}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ── 로그인 토큰 ──
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'dev-only-change-me')
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=2)

    # ── 실습과제: 게시판 REST API 를 호출할 때 쓰는 키 ──
    SECURITY_API_KEY = os.environ.get('SECURITY_API_KEY', 'dev-only-change-me')
    # 과잉권한 회수봇(privilege_revoke_bot.py) 이 /api/admin/users, /api/admin/revoke 를
    # 호출할 때 쓰는 키. 따로 안 정해두면 SECURITY_API_KEY 를 같이 쓴다.
    ADMIN_API_KEY = os.environ.get('ADMIN_API_KEY') or SECURITY_API_KEY
    # admin 을 가져도 되는 계정(정책 허용목록). 위반 조회·회수봇의 기준이 된다.
    # 쉼표로 구분: "admin,instructor". 비어 있으면 모든 admin 을 위반으로 본다.
    ADMIN_ALLOWLIST = [u.strip() for u in os.environ.get('ADMIN_ALLOWLIST', '').split(',') if u.strip()]
    # 거부(deny) 이벤트가 들어오면 게시판에 '보안' 공지글을 자동 등록할지.
    AUTO_POST_ON_DENY = os.environ.get('AUTO_POST_ON_DENY', '0') == '1'

    # ── IP 차단 요구사항 +a) 로그인 실패 자동 차단 ──
    # 같은 IP 에서 이만큼 연속으로 로그인 실패하면 즉시 차단하고 기존
    # security-alert-bot(n8n) 경로로 신고한다. alert_sender.py 와 이름을 맞춘다.
    LOGIN_FAIL_THRESHOLD = int(os.environ.get('LOGIN_FAIL_THRESHOLD', '5'))
    SECURITY_WEBHOOK_URL = os.environ.get(
        'SECURITY_WEBHOOK_URL', 'http://localhost:5678/webhook/security-events')
    STUDENT_NAME = os.environ.get('STUDENT_NAME', '본인이름으로_바꾸세요')

    # ── Graylog GELF 직통 신고 (privilege_revoke_bot.py 의 send_gelf 와 같은 방식) ──
    GELF_HOST = os.environ.get('GRAYLOG_HOST', 'localhost')
    GELF_PORT = int(os.environ.get('GRAYLOG_PORT', '12201'))

    # ── 보안 로그 파일(호스트의 Wazuh 에이전트가 읽어 감) ──
    # 기본: 이 폴더의 logs/security.log. 비우면(SECURITY_LOG_PATH=) 파일 기록을 끈다.
    SECURITY_LOG_PATH = os.environ.get(
        'SECURITY_LOG_PATH',
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs', 'security.log'))

    # ── 공공데이터(부산 테마여행) ──
    PUBLIC_API_KEY = _PUBLIC_API_KEY
    PUBLIC_API_URL = 'http://apis.data.go.kr/6260000/RecommendedService/getRecommendedKr'

    # ── 실행 ──
    FLASK_HOST = os.environ.get('FLASK_HOST', '127.0.0.1')
    FLASK_DEBUG = os.environ.get('FLASK_DEBUG', '1') == '1'
