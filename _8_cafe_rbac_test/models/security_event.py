from datetime import datetime

from extensions import db


class SecurityEvent(db.Model):
    """n8n 이 판정한 로그인 경보 1건을 저장한다 (과제 4)."""
    __tablename__ = 'security_events'
    id         = db.Column(db.Integer, primary_key=True)
    student    = db.Column(db.String(80),  nullable=False, index=True)   # 채점 증적용 식별자
    src_ip     = db.Column(db.String(45),  nullable=False)               # IPv6 까지 고려해 45자
    decision   = db.Column(db.String(10),  nullable=False)               # allow / deny
    severity   = db.Column(db.String(10))                                # High / Medium / Low
    reason     = db.Column(db.String(255))
    level      = db.Column(db.Integer)
    rule       = db.Column(db.String(50))
    fail_count = db.Column(db.Integer)
    source     = db.Column(db.String(50))                                # 예: privilege-guard (과잉권한 회수봇)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "student": self.student,
            "src_ip": self.src_ip,
            "decision": self.decision,
            "severity": self.severity,
            "reason": self.reason,
            "level": self.level,
            "rule": self.rule,
            "fail_count": self.fail_count,
            "source": self.source,
            "created_at": self.created_at.isoformat() + "Z",
        }
