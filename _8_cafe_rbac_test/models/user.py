from extensions import db

# ----------------- 미니 실습: RBAC 등급 -----------------
# 일반 0 / 골드 1 / 관리자 2  — 숫자가 클수록 넓은 권한.
ROLE_GENERAL = 0   # 일반 등급 — 최초 가입
ROLE_GOLD = 1      # 골드 등급 — 중간 관리자
ROLE_ADMIN = 2     # 관리자

ROLE_NAMES = {ROLE_GENERAL: '일반', ROLE_GOLD: '골드', ROLE_ADMIN: '관리자'}
# 강사님 저장소(_7_board_test)는 등급을 'user'/'gold'/'admin' 문자열로 쓴다.
# 이 앱은 숫자(0/1/2)로 두되, 그쪽 이름도 그대로 받아 같은 요청이 통하게 한다.
ROLE_NAME_TO_VALUE = {
    'general': ROLE_GENERAL, 'user': ROLE_GENERAL,
    'gold': ROLE_GOLD,
    'admin': ROLE_ADMIN,
}
# 응답에도 같은 문자열을 실어 준다(role_key) — 숫자만 보면 그쪽 도구가 못 읽는다.
ROLE_KEYS = {ROLE_GENERAL: 'user', ROLE_GOLD: 'gold', ROLE_ADMIN: 'admin'}


def parse_role(value):
    """'admin' 같은 이름과 2 같은 숫자를 모두 받아 등급 숫자로 바꾼다. 모르면 None."""
    if isinstance(value, str) and not value.strip().isdigit():
        return ROLE_NAME_TO_VALUE.get(value.strip().lower())
    try:
        role = int(value)
    except (TypeError, ValueError):
        return None
    return role if role in ROLE_NAMES else None


class User(db.Model):
    __tablename__ = 'cafe_users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    # 가입 시 무조건 0(일반)으로 시작한다. 등급 변경은 관리자 페이지에서만 가능.
    role = db.Column(db.Integer, nullable=False, default=ROLE_GENERAL)
    # 관리자 등급을 누가 부여했는지 기록 — 회수봇이 허용목록 밖 admin(=부여 근거가 없거나
    # 의심스러운 계정)을 탐지할 때 참고한다. 일반/골드로 내려가면 다시 비운다.
    role_granted_by = db.Column(db.String(80), nullable=True)
    # 감사(audit): 언제·왜 이 등급이 됐는가.
    role_granted_at = db.Column(db.DateTime, nullable=True)
    role_reason = db.Column(db.String(200), nullable=True)

    # ── 계정 잠금(account lockout) — 브루트포스 대응 ──
    # 로그인 실패가 임계를 넘으면 n8n(SOAR)이 잠근다. 잠긴 계정은 비번이 맞아도 423.
    is_locked = db.Column(db.Boolean, nullable=False, default=False, server_default='0')
    locked_at = db.Column(db.DateTime, nullable=True)
    lock_reason = db.Column(db.String(200), nullable=True)
    # 표시용 누적 실패 횟수(로그인 성공 시 0으로 초기화).
    failed_logins = db.Column(db.Integer, nullable=False, default=0, server_default='0')

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "role_name": ROLE_NAMES.get(self.role, '알수없음'),
            # 강사님 저장소와 같은 'user'/'gold'/'admin' 표기도 함께 준다.
            "role_key": ROLE_KEYS.get(self.role, 'unknown'),
            "role_granted_by": self.role_granted_by,
            "role_granted_at": self.role_granted_at.isoformat() if self.role_granted_at else None,
            "role_reason": self.role_reason,
            "is_locked": self.is_locked,
            "locked_at": self.locked_at.isoformat() if self.locked_at else None,
            "lock_reason": self.lock_reason,
            "failed_logins": self.failed_logins,
        }
