"""관리자(인가/RBAC) REST — 회원 권한 부여·회수 + IP 실차단 + 계정 잠금 + 인시던트 티켓.

접근 방식이 엔드포인트마다 다르다(기존 동작 그대로 보존):
  - grant/revoke            : X-API-Key(ADMIN_API_KEY) 전용 — 스크립트/Postman 바로 호출용.
  - users(PUT/DELETE)        : JWT(사람) + admin 등급 전용 — 관리자 페이지 화면 전용.
  - 그 외(목록/차단/잠금/인시던트) : X-API-Key 또는 JWT+admin 둘 다 허용(require_admin()).
"""
from datetime import datetime, timedelta

from flask import Blueprint, current_app, jsonify, request
from werkzeug.security import generate_password_hash

from extensions import db
from models import BlockedIP, Incident, SecurityEvent, User
from models.user import (ROLE_ADMIN, ROLE_GENERAL, ROLE_NAME_TO_VALUE, ROLE_NAMES,
                          parse_role)

from .rbac import check_admin_api_key, require_admin, role_required

admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')

_SEVERITY_RANK = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}


# ----------------- 요구사항 5) 관리자 페이지의 회원 조회/수정/삭제 -----------------
@admin_bp.route('/users', methods=['GET'])
def admin_list_users():
    """사람(관리자 로그인 JWT)과 자동화(privilege_revoke_bot.py 의 X-API-Key) 양쪽이 호출한다.

    ?role=general|gold|admin 으로 등급 필터링을 지원한다(회수봇이 admin만 조회)."""
    _admin_user, err = require_admin()
    if err:
        return err

    query = User.query
    role_filter = request.args.get('role')
    if role_filter:
        if role_filter.lower() not in ROLE_NAME_TO_VALUE:
            return jsonify({"msg": "role 파라미터는 general/gold/admin 중 하나여야 합니다."}), 400
        query = query.filter(User.role == ROLE_NAME_TO_VALUE[role_filter.lower()])

    users = query.order_by(User.id).all()
    return jsonify({"users": [u.to_dict() for u in users]}), 200


@admin_bp.route('/users/<int:user_id>', methods=['PUT'])
@role_required(ROLE_ADMIN)
def admin_update_user(current_user, user_id):
    target = User.query.get_or_404(user_id)
    data = request.get_json(silent=True) or {}

    if 'role' in data:
        try:
            new_role = int(data['role'])
        except (TypeError, ValueError):
            return jsonify({"msg": "role 값이 올바르지 않습니다."}), 400
        if new_role not in ROLE_NAMES:
            return jsonify({"msg": "role 은 0(일반)/1(골드)/2(관리자) 중 하나여야 합니다."}), 400
        if target.id == current_user.id and new_role != ROLE_ADMIN:
            return jsonify({"msg": "본인의 관리자 등급은 스스로 낮출 수 없습니다."}), 400
        # 관리자로 새로 올릴 때만 부여자를 기록하고, 관리자가 아니게 되면 비운다.
        if new_role == ROLE_ADMIN:
            if target.role != ROLE_ADMIN:
                target.role_granted_by = current_user.username
        else:
            target.role_granted_by = None
        target.role = new_role

    if 'username' in data and data['username']:
        new_username = data['username']
        if new_username != target.username and User.query.filter_by(username=new_username).first():
            return jsonify({"msg": "이미 존재하는 아이디입니다."}), 400
        target.username = new_username

    if data.get('password'):
        target.password = generate_password_hash(data['password'])

    db.session.commit()
    return jsonify(target.to_dict()), 200


@admin_bp.route('/users/<int:user_id>', methods=['DELETE'])
@role_required(ROLE_ADMIN)
def admin_delete_user(current_user, user_id):
    if user_id == current_user.id:
        return jsonify({"msg": "본인 계정은 삭제할 수 없습니다."}), 400
    target = User.query.get_or_404(user_id)
    db.session.delete(target)
    db.session.commit()
    return jsonify({"msg": f"{target.username} 계정을 삭제했습니다."}), 200


@admin_bp.route('/grant', methods=['POST'])
def admin_grant_user():
    """등급 부여 엔드포인트 — 회수(/api/admin/revoke)의 짝.

    회수봇을 시험할 때 '허용목록 밖 관리자'를 만들어 두는 용도로 쓴다. 관리자
    페이지(PUT /api/admin/users/<id>)와 달리 사람의 로그인 없이 X-API-Key 로만
    인증하므로 Postman·스크립트에서 바로 부를 수 있다.

    role 은 'admin' 처럼 이름으로도, 2 처럼 숫자로도 받는다. 생략하면 admin."""
    if not check_admin_api_key():
        return jsonify({"msg": "인증 실패: X-API-Key 가 없거나 올바르지 않습니다."}), 401

    data = request.get_json(silent=True) or {}
    username = data.get('username')
    if not username:
        return jsonify({"msg": "username 은 필수입니다."}), 400

    new_role = parse_role(data.get('role', 'admin'))
    if new_role is None:
        return jsonify({"msg": "role 은 general/gold/admin 또는 0/1/2 중 하나여야 합니다."}), 400

    target = User.query.filter_by(username=username).first()
    if not target:
        return jsonify({"msg": "사용자를 찾을 수 없습니다."}), 404

    old_role = target.role
    target.role = new_role
    # 관리자로 올릴 때만 부여자를 남긴다. 회수봇이 '누가 줬는지' 를 신고에 싣는다.
    target.role_granted_by = data.get('granted_by', 'api') if new_role == ROLE_ADMIN else None
    # 감사(audit): 언제·왜 이 등급이 됐는가.
    target.role_granted_at = datetime.now()
    target.role_reason = (data.get('reason') or '')[:200] or None
    db.session.commit()

    event = SecurityEvent(
        student=data.get('student', 'unknown'),
        src_ip=data.get('src_ip', '127.0.0.1'),
        decision='allow',
        severity='Medium',
        reason=data.get('reason') or f"{ROLE_NAMES[new_role]} 등급 부여: {username}",
        users=username,
        source=data.get('source', 'privilege-guard'),
        generated_at=data.get('generated_at'),
    )
    db.session.add(event)
    db.session.commit()

    return jsonify({
        "msg": f"{username} 계정에 {ROLE_NAMES[new_role]} 등급을 부여했습니다.",
        "username": username,
        "old_role": ROLE_NAMES.get(old_role),
        "new_role": ROLE_NAMES.get(new_role),
        "role_granted_by": target.role_granted_by,
        "event_id": event.id,
    }), 200


@admin_bp.route('/revoke', methods=['POST'])
def admin_revoke_user():
    """과잉권한 자동 회수 엔드포인트.

    privilege_revoke_bot.py 가 --revoke 로 직접 부르거나, 봇이 Graylog 에 신고한
    이벤트를 받아 n8n 이 대신 호출한다. 둘 다 사람이 아니라 자동화이므로 JWT 로그인
    없이 X-API-Key 로만 인증한다. 대상 계정을 일반(0) 등급으로 강등하고, 회수 사실을
    security_events 에 남겨 /security 대시보드에서도 보이게 한다."""
    if not check_admin_api_key():
        return jsonify({"msg": "인증 실패: X-API-Key 가 없거나 올바르지 않습니다."}), 401

    data = request.get_json(silent=True) or {}
    username = data.get('username')
    if not username:
        return jsonify({"msg": "username 은 필수입니다."}), 400

    target = User.query.filter_by(username=username).first()
    if not target:
        return jsonify({"msg": "사용자를 찾을 수 없습니다."}), 404

    old_role = target.role
    target.role = ROLE_GENERAL
    target.role_granted_by = None
    db.session.commit()

    event = SecurityEvent(
        student=data.get('student', 'unknown'),
        src_ip=data.get('src_ip', '127.0.0.1'),
        decision='deny',
        severity='High',
        reason=data.get('reason') or f"관리자 권한 자동 회수: {username}",
    )
    db.session.add(event)
    db.session.commit()

    return jsonify({
        "msg": f"{username} 계정의 관리자 권한을 회수했습니다.",
        "username": username,
        "old_role": ROLE_NAMES.get(old_role),
        "new_role": ROLE_NAMES.get(ROLE_GENERAL),
        "event_id": event.id,
    }), 200


@admin_bp.route('/violations', methods=['GET'])
def admin_list_violations():
    """정책 위반(허용목록 밖 관리자) 목록 — 회수봇이 참고용으로 쓸 수 있다.
    ?allowlist=admin,instructor 로 기준을 넘기면 .env 값보다 우선한다."""
    _admin_user, err = require_admin()
    if err:
        return err

    param = request.args.get('allowlist')
    allow = ([u.strip() for u in param.split(',') if u.strip()] if param
             else current_app.config.get('ADMIN_ALLOWLIST', []))
    admins = User.query.filter_by(role=ROLE_ADMIN).all()
    bad = [u for u in admins if u.username not in allow]
    return jsonify({
        "allowlist": allow,
        "count": len(bad),
        "violations": [u.to_dict() for u in bad],
    }), 200


# ----------------- 요구사항 +a) IP 차단(block) -----------------
@admin_bp.route('/block', methods=['POST'])
def admin_block_ip():
    """공격 IP 실차단(active response) → cafe_blocked_ips 에 추가. body: {ip, reason}
    이후 그 IP 로 오는 요청은 관리자 API 를 제외하고 미들웨어가 403 으로 막는다."""
    admin_user, err = require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    ip = (data.get('ip') or data.get('src_ip') or '').strip()
    if not ip:
        return jsonify({"msg": "ip(또는 src_ip) 는 필수입니다."}), 400

    actor = admin_user.username if admin_user else 'apikey'
    if db.session.get(BlockedIP, ip):
        return jsonify({"msg": "이미 차단된 IP 입니다.", "ip": ip, "blocked": True, "changed": False}), 200

    db.session.add(BlockedIP(ip=ip, reason=(data.get('reason') or f'관리자 차단 by {actor}')[:200], blocked_by=actor))
    # 감사기록: 대시보드(/security)에서도 보이도록 security_events 에 남긴다.
    event = SecurityEvent(
        student=(data.get('student') or actor)[:80],
        src_ip=ip,
        fail_count=int(data.get('fail_count') or 0),
        decision='deny',
        severity=data.get('severity', 'High'),
        reason=(data.get('reason') or f'IP 실차단: {ip}')[:255],
        users='',
        source=data.get('source', 'ip-guard'),
        generated_at=data.get('generated_at'),
    )
    db.session.add(event)
    db.session.commit()
    return jsonify({"msg": "IP 차단 완료", "ip": ip, "blocked": True, "changed": True,
                    "event_id": event.id, "blocked_by": actor}), 200


@admin_bp.route('/unblock', methods=['POST'])
def admin_unblock_ip():
    """IP 차단 해제. body: {ip}"""
    _admin_user, err = require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    ip = (data.get('ip') or data.get('src_ip') or '').strip()
    if not ip:
        return jsonify({"msg": "ip 는 필수입니다."}), 400

    row = db.session.get(BlockedIP, ip)
    if row:
        db.session.delete(row)
        db.session.commit()
    return jsonify({"msg": "차단 해제 완료", "ip": ip, "blocked": False}), 200


@admin_bp.route('/blocked', methods=['GET'])
def admin_list_blocked():
    """차단된 IP 목록."""
    _admin_user, err = require_admin()
    if err:
        return err
    rows = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).all()
    return jsonify({"count": len(rows), "blocked": [r.to_dict() for r in rows]}), 200


# ----------------- 계정 잠금(account lockout) -----------------
@admin_bp.route('/lock', methods=['POST'])
def admin_lock_account():
    """계정 잠금(브루트포스 대응) → is_locked=True. n8n 이 호출한다.
    body: {username, reason, student, src_ip, fail_count, severity}
    잠금이 실제로 일어나면 security_events 에 감사기록(source='login-guard')을 남긴다."""
    admin_user, err = require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    if not username:
        return jsonify({"msg": "username 은 필수입니다."}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"msg": f"없는 사용자: {username}"}), 404

    actor = admin_user.username if admin_user else 'apikey'
    if user.is_locked:
        return jsonify({"msg": "이미 잠긴 계정", "username": username,
                        "locked": True, "changed": False}), 200

    user.is_locked = True
    user.locked_at = datetime.now()
    user.lock_reason = (data.get('reason') or f'브루트포스 자동 잠금 by {actor}')[:200]
    event = SecurityEvent(
        student=(data.get('student') or actor)[:80],
        src_ip=data.get('src_ip') or '0.0.0.0',
        fail_count=int(data.get('fail_count') or 0),
        decision='deny',
        severity=data.get('severity', 'High'),
        reason=(data.get('reason') or f'계정 잠금: {username} (브루트포스)')[:255],
        users=username,
        source=data.get('source', 'login-guard'),
        generated_at=data.get('generated_at'),
    )
    db.session.add(event)
    db.session.commit()
    return jsonify({"msg": "계정 잠금 완료", "username": username, "locked": True,
                    "changed": True, "event_id": event.id, "locked_by": actor}), 200


@admin_bp.route('/unlock', methods=['POST'])
def admin_unlock_account():
    """계정 잠금 해제 → is_locked=False + 실패 카운트 초기화. body: {username}"""
    _admin_user, err = require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    username = (data.get('username') or '').strip()
    if not username:
        return jsonify({"msg": "username 은 필수입니다."}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"msg": f"없는 사용자: {username}"}), 404

    user.is_locked = False
    user.failed_logins = 0
    user.lock_reason = None
    db.session.commit()
    return jsonify({"msg": "잠금 해제 완료", "username": username, "locked": False}), 200


# ----------------- 인시던트(사고) 티켓 -----------------
def _build_incident_summary(src_ip, events):
    """security_events 를 사람이 읽는 인시던트 요약(타임라인·집계·조치)으로 취합."""
    by_source, actions = {}, set()
    worst = 'Low'
    lines = []
    for e in events:
        by_source[e.source] = by_source.get(e.source, 0) + 1
        if e.decision:
            actions.add(e.decision)
        if _SEVERITY_RANK.get(e.severity, 1) > _SEVERITY_RANK.get(worst, 1):
            worst = e.severity
        when = (e.created_at.strftime('%Y-%m-%d %H:%M:%S') if e.created_at
                else (e.generated_at or '?'))
        lines.append(f"- {when} [{e.severity}/{e.source}] {e.reason or ''} (users={e.users or '-'})")

    first = events[-1].created_at if events and events[-1].created_at else None
    last = events[0].created_at if events and events[0].created_at else None
    src_summary = ', '.join(f'{k}×{v}' for k, v in sorted(by_source.items(), key=lambda kv: str(kv[0])))
    action_text = ', '.join(sorted(actions)) or '없음'
    summary = (
        f"[인시던트 요약] 출발지 {src_ip}\n"
        f"- 관련 이벤트: {len(events)}건 ({src_summary})\n"
        f"- 최초/최종: {first} ~ {last}\n"
        f"- 취해진 조치: {action_text}\n"
        f"- 최고 심각도: {worst}\n"
        f"[타임라인]\n" + "\n".join(lines[:20])
    )
    return summary, worst, action_text, len(events)


@admin_bp.route('/incident', methods=['POST'])
def admin_create_incident():
    """인시던트 티켓 생성/갱신. body: {src_ip, title?, severity?, student?, hours?}

    같은 src_ip 의 '열린' 티켓이 있으면 갱신하고(중복 방지), 없으면 새로 만든다.
    요약은 최근 hours(기본 24)시간의 security_events 를 자동으로 취합한다."""
    admin_user, err = require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    src_ip = (data.get('src_ip') or data.get('ip') or '').strip()
    if not src_ip:
        return jsonify({"msg": "src_ip 는 필수입니다."}), 400

    actor = admin_user.username if admin_user else 'apikey'
    hours = int(data.get('hours') or 24)
    since = datetime.now() - timedelta(hours=hours)
    # 같은 src_ip 의 '마지막으로 종료된 티켓' 이후 사건만 취합한다 — 이미 처리·종료한
    # 사건을 새 티켓이 다시 흡수하지 않게 하기 위해서다. 같은 초 경계는 포함(>=) 쪽으로:
    # 새 증거를 놓치는 것보다 한 건 겹치는 편이 안전하다.
    last_closed = (Incident.query
                   .filter(Incident.src_ip == src_ip, Incident.status == 'closed',
                           Incident.closed_at.isnot(None))
                   .order_by(Incident.closed_at.desc()).first())
    if last_closed and last_closed.closed_at > since:
        since = last_closed.closed_at
    events = (SecurityEvent.query
              .filter(SecurityEvent.src_ip == src_ip, SecurityEvent.created_at >= since)
              .order_by(SecurityEvent.created_at.desc()).all())
    summary, worst, actions, count = _build_incident_summary(src_ip, events)
    severity = data.get('severity') or worst

    incident = Incident.query.filter_by(src_ip=src_ip, status='open').first()
    created = incident is None
    if created:
        incident = Incident(src_ip=src_ip, status='open')
        db.session.add(incident)

    incident.title = (data.get('title') or f'보안 인시던트: {src_ip} ({count}건)')[:200]
    # 심각도는 '내려가지 않는다': 요청값·취합 최고값·기존 티켓 값 중 가장 높은 것
    # (Critical 티켓에 나중에 Medium 경보가 합쳐져도 Critical 을 유지해야 한다).
    incident.severity = max((severity, worst, incident.severity or 'Low'),
                            key=lambda s: _SEVERITY_RANK.get(s, 0))
    incident.summary = summary
    incident.event_count = count
    incident.actions = actions[:255]
    incident.student = (data.get('student') or actor)[:50]
    db.session.commit()

    return jsonify({"msg": "인시던트 생성" if created else "인시던트 갱신",
                    "created": created,
                    "incident": incident.to_dict()}), (201 if created else 200)


@admin_bp.route('/incidents', methods=['GET'])
def admin_list_incidents():
    """인시던트 목록. ?status=open|closed 로 거를 수 있다."""
    _admin_user, err = require_admin()
    if err:
        return err

    status = request.args.get('status')
    query = Incident.query
    if status in ('open', 'closed'):
        query = query.filter_by(status=status)
    rows = query.order_by(Incident.updated_at.desc()).all()
    return jsonify({"count": len(rows), "incidents": [r.to_dict() for r in rows]}), 200


@admin_bp.route('/incident/close', methods=['POST'])
def admin_close_incident():
    """인시던트 종료(status=closed). body: {id}"""
    _admin_user, err = require_admin()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    try:
        incident_id = int(data.get('id') or 0)
    except (TypeError, ValueError):
        return jsonify({"msg": "id 가 올바르지 않습니다."}), 400

    incident = db.session.get(Incident, incident_id)
    if not incident:
        return jsonify({"msg": "없는 인시던트"}), 404

    incident.status = 'closed'
    incident.closed_at = datetime.now()
    db.session.commit()
    return jsonify({"msg": "인시던트 종료", "incident": incident.to_dict()}), 200
