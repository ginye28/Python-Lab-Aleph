from datetime import datetime

from extensions import db


class Incident(db.Model):
    """보안 인시던트(사고) 티켓 — 탐지·대응 결과를 한 건의 추적 단위로 남긴다.

    같은 출발지(src_ip)의 '열린' 티켓은 하나만 두고(중복 방지), 이벤트가 쌓이면
    요약을 갱신한다. 실무의 티켓(Jira/ServiceNow) 축소판 — 감사·인계에 쓴다.
    """
    __tablename__ = 'cafe_incidents'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    src_ip = db.Column(db.String(45), index=True)
    severity = db.Column(db.String(10), default='Medium')          # Low|Medium|High|Critical
    status = db.Column(db.String(12), default='open', index=True)  # open|closed
    summary = db.Column(db.Text)            # 자동 취합된, 사람이 읽는 요약(타임라인·조치)
    event_count = db.Column(db.Integer, default=0)
    actions = db.Column(db.String(255))     # 취해진 조치 요약
    student = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    closed_at = db.Column(db.DateTime)

    def to_dict(self):
        return {
            "id": self.id, "title": self.title, "src_ip": self.src_ip,
            "severity": self.severity, "status": self.status,
            "summary": self.summary, "event_count": self.event_count,
            "actions": self.actions, "student": self.student,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
        }
