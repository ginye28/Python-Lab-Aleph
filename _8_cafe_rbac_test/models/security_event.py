from extensions import db


class SecurityEvent(db.Model):
    __tablename__ = 'security_events'
    id = db.Column(db.Integer, primary_key=True)
    student = db.Column(db.String(80), nullable=False)
    src_ip = db.Column(db.String(45), nullable=False)
    decision = db.Column(db.String(10), nullable=False)   # 'allow' | 'deny'
    severity = db.Column(db.String(10))                   # 'Low' | 'Medium' | 'High'
    reason = db.Column(db.String(255))
    # 아래는 강사님 저장소(_7_board_test)의 security_events 와 필드를 맞춘 것.
    fail_count = db.Column(db.Integer, nullable=False, default=0, server_default='0')
    users = db.Column(db.String(255))        # 시도된 계정들
    last_seen = db.Column(db.String(32))     # 마지막 시도 시각(보낸 쪽 표기 그대로)
    window_min = db.Column(db.Integer)       # 집계 구간(분)
    source = db.Column(db.String(50), default='login_guard')   # 어느 탐지기가 보냈나
    generated_at = db.Column(db.String(32))  # 보낸 쪽이 만든 시각
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "student": self.student,
            "src_ip": self.src_ip,
            "decision": self.decision,
            "severity": self.severity,
            "reason": self.reason,
            "fail_count": self.fail_count,
            "users": self.users,
            "last_seen": self.last_seen,
            "window_min": self.window_min,
            "source": self.source,
            "generated_at": self.generated_at,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
