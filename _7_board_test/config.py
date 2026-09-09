"""설정 한 곳에 모으기.

비밀값(DB 비밀번호·JWT 키·API 키)은 코드에 쓰지 않고 같은 폴더의 .env 에서 읽는다.
.env 는 절대 깃에 올리지 않는다(.gitignore). 제출·공유용으로는 .env.example 만 남긴다.
"""
import os
from datetime import timedelta

from dotenv import load_dotenv

load_dotenv()  # .env → 환경변수 (import 시점 1회)


class Config:
  # ── 데이터베이스 (도커 MySQL) ──
  SQLALCHEMY_DATABASE_URI = os.environ.get(
      'DATABASE_URL',
      # 기본값에는 비밀번호를 두지 않는다 — 반드시 .env 의 DATABASE_URL 을 쓴다
      'mysql+pymysql://<user>:<password>@localhost:3306/my_new_board_db',
  )
  SQLALCHEMY_TRACK_MODIFICATIONS = False

  # ── 로그인 토큰 ──
  JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'dev-only-change-me')
  JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=2)

  # ── 보안 이벤트 REST (n8n 이 호출) ──
  # 값이 비어 있으면 POST 는 항상 401 (fail-closed: 실수로 열어두지 않는다)
  SECURITY_API_KEY = os.environ.get('SECURITY_API_KEY', '')
  # 거부(deny) 시 게시판에 '보안' 공지글 자동 등록
  AUTO_POST_ON_DENY = os.environ.get('AUTO_POST_ON_DENY', '0') == '1'

  # ── 공공데이터(부산 테마여행) ──
  PUBLIC_API_KEY = os.environ.get('PUBLIC_API_KEY')
  PUBLIC_API_URL = (
      'http://apis.data.go.kr/6260000/RecommendedService/getRecommendedKr'
  )
