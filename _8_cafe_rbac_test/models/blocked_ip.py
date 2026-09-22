from datetime import datetime

from extensions import db


class BlockedIP(db.Model):
    """차단된 IP 목록(실차단/active response). 미들웨어가 매 요청 이 표를 보고 403.

    n8n(SOAR)이 공격 IP 를 여기에 추가하면, 그 IP 의 이후 요청은 앱에 닿지 못한다.
    """
    __tablename__ = 'blocked_ips'
    ip = db.Column(db.String(45), primary_key=True)   # IPv6 까지 45자
    reason = db.Column(db.String(200))
    blocked_by = db.Column(db.String(80))
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "ip": self.ip,
            "reason": self.reason,
            "blocked_by": self.blocked_by,
            "blocked_at": self.blocked_at.isoformat() + "Z" if self.blocked_at else None,
        }
