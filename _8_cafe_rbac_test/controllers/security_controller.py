"""보안 이벤트 수집 API (실습과제: 경보 자동화 봇) — n8n 이 판정 결과를 보내 저장하는 곳."""
import os

from flask import Blueprint, current_app, jsonify, request
from werkzeug.security import generate_password_hash

from extensions import db
from models import Incident, Post, SecurityEvent, User
from models.user import ROLE_GENERAL

from .gelf import send_gelf
from .pagination import SortError, paginate, severity_rank
from .rbac import client_ip

security_bp = Blueprint('security', __name__)

# 정렬 허용 컬럼(화이트리스트) — 화면의 표 머리글을 누르면 이 이름이 날아온다.
# severity 는 글자가 아니라 서열로 정렬한다(pagination.severity_rank 설명 참고).
_EVENT_SORTS = {
    'created_at': SecurityEvent.created_at,
    'decision': SecurityEvent.decision,
    'severity': severity_rank(SecurityEvent.severity),
    'fail_count': SecurityEvent.fail_count,
    'student': SecurityEvent.student,
    'src_ip': SecurityEvent.src_ip,
    'id': SecurityEvent.id,
}

_INCIDENT_SORTS = {
    'created_at': Incident.created_at,
    'updated_at': Incident.updated_at,
    'closed_at': Incident.closed_at,
    'severity': severity_rank(Incident.severity),
    'status': Incident.status,
    'event_count': Incident.event_count,
    'src_ip': Incident.src_ip,
    'id': Incident.id,
}


def _create_security_post(event):
    """심화: 거부 이벤트를 게시판 '보안' 공지글로 자동 등록한다(작성자 = 시스템 계정).

    AUTO_POST_ON_DENY=1 일 때만 불린다. 봇 계정이 없으면 무작위 비밀번호로 만들어
    두고(로그인 용도가 아니라 글쓴이 표시용) 그 계정 이름으로 글을 남긴다."""
    bot = User.query.filter_by(username='soarbot').first()
    if not bot:
        bot = User(username='soarbot',
                   password=generate_password_hash(os.urandom(16).hex()),
                   role=ROLE_GENERAL)
        db.session.add(bot)
        db.session.flush()

    post = Post(
        title=f'[보안][{event.student}] {event.src_ip} 접근 거부 ({event.severity})',
        content=(f'{event.reason}\n시도 계정: {event.users}\n'
                 f'마지막 시도: {event.last_seen}\n수집: {event.generated_at}'),
        category='보안', author_id=bot.id)
    db.session.add(post)
    db.session.flush()
    return post.id


@security_bp.route('/api/security/events', methods=['POST'])
def create_security_event():
    # n8n 이 호출하는 엔드포인트. 헤더의 API 키로 인증한다 (JWT 로그인과는 별개).
    if request.headers.get('X-API-Key') != current_app.config.get('SECURITY_API_KEY'):
        # S6 인증 공격 탐지 — 키를 추측해 두드리는 것을 신고한다.
        # 시도된 키 값 자체는 절대 남기지 않는다(그 자체가 비밀 후보다).
        try:
            send_gelf(f"admin api auth failed {request.path[:80]}", rule='admin-auth-fail',
                      src_ip=client_ip(), path=request.path[:120], code=401)
        except Exception:
            pass
        return jsonify({"msg": "인증 실패: X-API-Key 가 없거나 올바르지 않습니다."}), 401

    data = request.get_json(silent=True) or {}
    student = data.get('student')
    src_ip = data.get('src_ip')
    decision = data.get('decision')

    if not student or not src_ip or decision not in ('allow', 'deny'):
        return jsonify({"msg": "student, src_ip, decision(allow|deny) 은 필수입니다."}), 400

    event = SecurityEvent(
        student=student,
        src_ip=src_ip,
        decision=decision,
        severity=data.get('severity', 'Low'),
        reason=data.get('reason'),
        fail_count=int(data.get('fail_count') or 0),
        users=data.get('users'),
        last_seen=data.get('last_seen'),
        window_min=data.get('window_min'),
        source=data.get('source', 'login_guard'),
        generated_at=data.get('generated_at'),
    )
    db.session.add(event)
    db.session.flush()   # event.id 확보

    post_id = None
    if decision == 'deny' and current_app.config.get('AUTO_POST_ON_DENY'):
        post_id = _create_security_post(event)

    db.session.commit()   # 이벤트 + 공지글을 한 트랜잭션으로 함께 커밋한다.

    result = event.to_dict()
    result['post_id'] = post_id
    return jsonify(result), 201


@security_bp.route('/api/security/events', methods=['GET'])
def list_security_events():
    """조회는 키 없이(수업 확인용).

    필터: ?student= · ?decision=allow|deny · ?severity=Low|Medium|High|Critical
    페이징: ?page=1 &per_page=20 (최대 100, 예전 ?limit= 도 받는다)
    정렬:  ?sort=created_at|decision|severity|fail_count|student|src_ip|id
           &order=asc|desc (기본 created_at desc = 최신 먼저)"""
    student = request.args.get('student')
    decision = request.args.get('decision')
    severity = request.args.get('severity')

    query = SecurityEvent.query
    if student:
        query = query.filter_by(student=student)
    if decision in ('allow', 'deny'):
        query = query.filter_by(decision=decision)
    if severity:
        query = query.filter_by(severity=severity)

    try:
        rows, meta = paginate(query, request.args, _EVENT_SORTS, SecurityEvent.id)
    except SortError as e:
        return jsonify({"msg": str(e)}), 400

    return jsonify({"count": len(rows), "events": [r.to_dict() for r in rows], **meta})


@security_bp.route('/api/security/events/summary', methods=['GET'])
def security_events_summary():
    """허용/거부 건수 + 거부 실패횟수 상위 IP 5개."""
    student = request.args.get('student')

    q_decision = db.session.query(SecurityEvent.decision, db.func.count(SecurityEvent.id))
    q_top = (db.session.query(SecurityEvent.src_ip, db.func.sum(SecurityEvent.fail_count))
             .filter(SecurityEvent.decision == 'deny'))
    if student:
        q_decision = q_decision.filter(SecurityEvent.student == student)
        q_top = q_top.filter(SecurityEvent.student == student)

    by_decision = dict(q_decision.group_by(SecurityEvent.decision).all())
    top = (q_top.group_by(SecurityEvent.src_ip)
           .order_by(db.func.sum(SecurityEvent.fail_count).desc()).limit(5).all())

    return jsonify({
        "student": student,
        "by_decision": by_decision,
        "top_deny_ips": [{"src_ip": ip, "fails": int(n or 0)} for ip, n in top],
    })


@security_bp.route('/api/security/incidents', methods=['GET'])
def list_security_incidents():
    """인시던트 티켓 목록 — 조회는 키 없이(대시보드가 쓴다).

    생성/종료는 그대로 관리자 키가 필요한 /api/admin/incident 쪽이다(읽기 전용).

    필터: ?status=open|closed · ?student= · ?severity=Low|Medium|High|Critical
    페이징: ?page=1 &per_page=20 (최대 100, 예전 ?limit= 도 받는다)
    정렬:  ?sort=created_at|updated_at|closed_at|severity|status|event_count|src_ip|id
           &order=asc|desc (기본 created_at desc = 최신 먼저)"""
    status = request.args.get('status')
    student = request.args.get('student')
    severity = request.args.get('severity')

    query = Incident.query
    if status in ('open', 'closed'):
        query = query.filter_by(status=status)
    if student:
        query = query.filter_by(student=student)
    if severity:
        query = query.filter_by(severity=severity)

    try:
        rows, meta = paginate(query, request.args, _INCIDENT_SORTS, Incident.id)
    except SortError as e:
        return jsonify({"msg": str(e)}), 400

    return jsonify({"count": len(rows), "incidents": [r.to_dict() for r in rows], **meta})


@security_bp.route('/api/security/incidents/summary', methods=['GET'])
def security_incidents_summary():
    """상태별 티켓 수 + 열린 티켓의 심각도 분포(대시보드 카드용)."""
    student = request.args.get('student')

    q_status = db.session.query(Incident.status, db.func.count(Incident.id))
    q_severity = (db.session.query(Incident.severity, db.func.count(Incident.id))
                  .filter(Incident.status == 'open'))
    if student:
        q_status = q_status.filter(Incident.student == student)
        q_severity = q_severity.filter(Incident.student == student)

    return jsonify({
        "by_status": dict(q_status.group_by(Incident.status).all()),
        "open_by_severity": dict(q_severity.group_by(Incident.severity).all()),
    })


@security_bp.route('/api/security/students', methods=['GET'])
def list_security_students():
    """대시보드 드롭다운용 — 기록이 있는 학생 목록."""
    rows = (db.session.query(SecurityEvent.student)
            .distinct().order_by(SecurityEvent.student).all())
    return jsonify({"students": [r[0] for r in rows]})
