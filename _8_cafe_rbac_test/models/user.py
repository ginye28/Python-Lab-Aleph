from extensions import db

# ----------------- 등급(권한) 정의 (과제: 접근 제어 테스트) -----------------
# 카페이야기 등급 체계: 일반(가입 시 기본) < 골드(중간 관리자) < 관리자
ROLE_GENERAL = 0
ROLE_GOLD = 1
ROLE_ADMIN = 2
ROLE_LABELS = {ROLE_GENERAL: '일반', ROLE_GOLD: '골드', ROLE_ADMIN: '관리자'}


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    # 0=일반(기본, 최초 가입), 1=골드(중간 관리자), 2=관리자
    role = db.Column(db.Integer, nullable=False, default=ROLE_GENERAL)
    # 권한 부여/회수 감사 추적용 (누가, 언제, 왜 이 등급을 줬는지)
    role_granted_by = db.Column(db.String(80), nullable=True)
    role_granted_at = db.Column(db.DateTime, nullable=True)
    role_reason = db.Column(db.String(200), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "role_label": ROLE_LABELS.get(self.role, "알수없음"),
            "role_granted_by": self.role_granted_by,
            "role_granted_at": self.role_granted_at.isoformat() + "Z" if self.role_granted_at else None,
            "role_reason": self.role_reason,
        }
