"""보안 이벤트 수집 API (과제 4) — n8n 이 판정 결과를 보내 저장하는 곳.

n8n 컨테이너 -> 호스트의 이 서버로 POST 된다.
컨테이너 안에서 localhost 는 컨테이너 자신이므로, n8n 쪽 URL 은
  http://host.docker.internal:5000/api/security/events
를 써야 한다. (문제지 과제 4 힌트)
"""
import hmac

from flask import Blueprint, current_app, jsonify, request

from extensions import db
from models import SecurityEvent

security_bp = Blueprint('security', __name__, url_prefix='/api/security')

REQUIRED_EVENT_FIELDS = ("student", "src_ip", "decision")


def _check_api_key():
    """인증 실패 사유를 담은 응답을 돌려주고, 통과면 None 을 돌려준다."""
    expected = current_app.config.get("SECURITY_API_KEY")
    if not expected:
        # 서버가 키를 설정하지 않은 상태 — 인증을 통과시키면 안 된다
        return jsonify({"msg": "서버에 SECURITY_API_KEY 가 설정되지 않았습니다."}), 500
    sent = request.headers.get("X-API-Key")
    if not sent:
        return jsonify({"msg": "X-API-Key 헤더가 없습니다."}), 401
    # 타이밍 공격을 피하려고 단순 == 대신 상수시간 비교를 쓴다
    if not hmac.compare_digest(sent, expected):
        return jsonify({"msg": "X-API-Key 가 올바르지 않습니다."}), 401
    return None


def _as_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


@security_bp.route('/events', methods=['POST'])
def create_security_event():
    # ① 인증 먼저 (D1·D2 순서: 키가 틀리면 본문 검증 전에 401)
    denied = _check_api_key()
    if denied:
        return denied

    # ② 본문 검증
    data = request.get_json(silent=True) or {}
    missing = [f for f in REQUIRED_EVENT_FIELDS if not data.get(f)]
    if missing:
        return jsonify({"msg": "필수값 누락", "missing": missing}), 400

    if data["decision"] not in ("allow", "deny"):
        return jsonify({"msg": "decision 은 allow 또는 deny 여야 합니다."}), 400

    # ③ 저장
    event = SecurityEvent(
        student    = str(data["student"])[:80],
        src_ip     = str(data["src_ip"])[:45],
        decision   = data["decision"],
        severity   = (data.get("severity") or "Low"),
        reason     = (str(data["reason"])[:255] if data.get("reason") else None),
        level      = _as_int(data.get("level")),
        rule       = (str(data["rule"])[:50] if data.get("rule") else None),
        fail_count = _as_int(data.get("fail_count")) or 0,
    )
    db.session.add(event)
    db.session.commit()
    return jsonify(event.to_dict()), 201


@security_bp.route('/events', methods=['GET'])
def list_security_events():
    """이벤트 조회 (인증 없음). student 를 주면 본인 것만, 없으면 전체(대시보드용)."""
    student = request.args.get("student")
    decision = request.args.get("decision")
    limit = min(request.args.get("limit", default=20, type=int) or 20, 100)

    query = SecurityEvent.query
    if student:
        query = query.filter_by(student=student)
    if decision in ("allow", "deny"):
        query = query.filter_by(decision=decision)

    rows = (query
            .order_by(SecurityEvent.created_at.desc(), SecurityEvent.id.desc())
            .limit(limit)
            .all())
    return jsonify({"student": student, "count": len(rows),
                    "events": [r.to_dict() for r in rows]}), 200


@security_bp.route('/events/summary', methods=['GET'])
def security_event_summary():
    """(심화 S1) 허용/거부 건수와 거부 상위 IP. student 없으면 전체 집계."""
    student = request.args.get("student")

    q1 = db.session.query(SecurityEvent.decision, db.func.count(SecurityEvent.id))
    q2 = (db.session.query(SecurityEvent.src_ip, db.func.sum(SecurityEvent.fail_count).label("c"))
          .filter(SecurityEvent.decision == "deny"))
    if student:
        q1 = q1.filter(SecurityEvent.student == student)
        q2 = q2.filter(SecurityEvent.student == student)

    by_decision = dict(q1.group_by(SecurityEvent.decision).all())
    top_deny = (q2.group_by(SecurityEvent.src_ip)
                .order_by(db.desc("c"))
                .limit(5).all())
    return jsonify({
        "student": student,
        "by_decision": by_decision,
        "top_deny_ips": [{"src_ip": ip, "fails": int(c or 0)} for ip, c in top_deny],
    }), 200


@security_bp.route('/students', methods=['GET'])
def list_security_students():
    """대시보드 드롭다운용 — 기록이 있는 학생 목록."""
    rows = (db.session.query(SecurityEvent.student)
            .distinct().order_by(SecurityEvent.student).all())
    return jsonify({"students": [r[0] for r in rows]}), 200
