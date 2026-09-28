from extensions import db


class BlockedIP(db.Model):
    """차단된 IP 목록(실차단). before_request 미들웨어가 매 요청 이 표를 보고 403 처리한다.

    관리자 페이지(또는 회수봇처럼 X-API-Key 를 쓰는 자동화)가 여기에 IP 를 추가하면,
    그 IP 로 들어오는 이후 요청은 관리자 API(/api/admin/*)를 제외하고 앱에 닿지 못한다.
    """
    __tablename__ = 'cafe_blocked_ips'
    ip = db.Column(db.String(45), primary_key=True)   # IPv6 까지 45자
    reason = db.Column(db.String(200))
    blocked_by = db.Column(db.String(80))
    blocked_at = db.Column(db.DateTime, server_default=db.func.now())

    def to_dict(self):
        return {
            "ip": self.ip,
            "reason": self.reason,
            "blocked_by": self.blocked_by,
            "blocked_at": self.blocked_at.isoformat() if self.blocked_at else None,
        }
