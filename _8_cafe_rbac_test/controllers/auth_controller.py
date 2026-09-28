"""회원가입 / 로그인 / 내 정보."""
import requests
from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required
from werkzeug.security import check_password_hash, generate_password_hash

from extensions import db
from models import BlockedIP, User
from models.user import ROLE_GENERAL, ROLE_KEYS, ROLE_NAMES

from .gelf import send_gelf
from .rbac import client_ip
from .seclog import write_seclog

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')

# 같은 IP 의 연속 로그인 실패 횟수. 프로세스 메모리에만 두는 카운터라 서버를
# 재시작하면 초기화된다 — 실습 규모에선 충분하고, 실서비스는 Redis 등으로 옮겨야 한다.
_login_fail_counts = {}


def _report_login_bruteforce(ip, fail_count):
    """연속 실패 임계치를 넘긴 IP 를 즉시 차단하고, 두 경로로 신고한다.

    ① 기존 security-alert-bot(n8n) 웹훅 — alert_sender.py 와 같은 payload 형태로
       보내서, 이미 Publish 된 워크플로(판정 → 거부인가? → 슬랙/디스코드/텔레그램 +
       게시판 저장)를 그대로 탄다.
    ② Graylog GELF 직통 신고.

    둘 다 n8n/Graylog 가 꺼져 있어도 로그인 응답 자체는 막히지 않도록 실패를 삼킨다.
    """
    if not db.session.get(BlockedIP, ip):
        db.session.add(BlockedIP(
            ip=ip,
            reason=f'로그인 {fail_count}회 연속 실패로 자동 차단',
            blocked_by='system',
        ))
        db.session.commit()

    payload = {
        "student": current_app.config.get('STUDENT_NAME'),
        "alerts": [{
            "ip": ip,
            # 판정(Code) 노드의 DENY_LEVEL(기본 10) 이상이어야 deny 로 분류된다.
            "level": 10,
            "rule": "login-bruteforce",
            "fail_count": fail_count,
        }],
    }
    try:
        requests.post(current_app.config.get('SECURITY_WEBHOOK_URL'), json=payload, timeout=5)
    except requests.RequestException as e:
        print(f"[진단] 로그인 실패 신고를 n8n 으로 못 보냈습니다: {e}")

    send_gelf(f"login bruteforce: '{ip}' failed {fail_count} times in a row",
              rule='login-bruteforce', src_ip=ip, fail_count=fail_count)


@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"msg": "아이디와 비밀번호를 입력해주세요."}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "이미 존재하는 아이디입니다."}), 400

    hashed_password = generate_password_hash(password)
    # 회원가입은 무조건 일반(0) 등급으로 시작한다.
    new_user = User(username=username, password=hashed_password, role=ROLE_GENERAL)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "회원가입이 완료되었습니다. (일반 등급으로 시작합니다)"}), 201


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    ip = client_ip()

    # ① 잠긴 계정은 비밀번호가 맞아도 거부한다(423 Locked).
    if user and user.is_locked:
        send_gelf(f"login attempt on LOCKED account '{username}'",
                  rule='login-bruteforce', username=username, src_ip=ip, locked='1')
        write_seclog('login_failed', username, ip)   # 잠긴 계정 시도도 실패로 기록(Wazuh)
        return jsonify({
            "msg": "계정이 잠겨 있습니다. 관리자에게 문의하세요.",
            "locked": True,
        }), 423

    # ② 인증 실패 → 실패 카운트 증가 + Graylog 신고, 임계 넘으면 IP 자동 차단.
    if not user or not check_password_hash(user.password, password):
        if user:
            user.failed_logins = (user.failed_logins or 0) + 1
            db.session.commit()
        send_gelf(f"failed login for '{username}' from {ip}",
                  rule='login-bruteforce', username=username or '(unknown)',
                  src_ip=ip, count=1)
        write_seclog('login_failed', username or '(unknown)', ip)   # 호스트 로그 → Wazuh

        fail_count = _login_fail_counts.get(ip, 0) + 1
        _login_fail_counts[ip] = fail_count

        threshold = current_app.config.get('LOGIN_FAIL_THRESHOLD', 5)
        if fail_count >= threshold:
            _login_fail_counts.pop(ip, None)  # 차단됐으니 이 IP 카운터는 정리한다.
            _report_login_bruteforce(ip, fail_count)
            return jsonify({
                "msg": f"로그인 {fail_count}회 연속 실패로 IP 가 차단되었습니다.",
                "ip": ip,
                "blocked": True,
            }), 403

        return jsonify({"msg": "아이디 또는 비밀번호가 올바르지 않습니다."}), 401

    # ③ 성공 → 실패 카운터(메모리·DB) 초기화 후 토큰 발급.
    _login_fail_counts.pop(ip, None)
    if user.failed_logins:
        user.failed_logins = 0
        db.session.commit()

    # 성공도 남긴다. 실패만 모으면 "누가 결국 뚫렸는가"를 알 수 없다 — 심야 접속·계정
    # 탈취·한 계정 다중 IP 같은 탐지는 전부 성공 기록이 있어야 만든다. 남기는 값은
    # 계정명·등급·출발지 IP 뿐(비밀번호·토큰은 절대 남기지 않는다).
    send_gelf(f"successful login for '{username}' from {ip}",
              rule='login-success', username=username, src_ip=ip,
              role=ROLE_KEYS.get(user.role, ''))
    write_seclog('login_success', username, ip)

    # role 은 토큰 안에도 넣어 두지만(참고용), 실제 인가 검사는 매번 DB 를 다시 조회해서
    # 판단한다 — 관리자가 등급을 바꾸면 재로그인 없이도 바로 반영되게 하기 위해서다.
    access_token = create_access_token(
        identity=str(user.id),
        additional_claims={"role": user.role, "username": user.username},
    )
    return jsonify({
        "access_token": access_token,
        "username": user.username,
        "role": user.role,
        "role_name": ROLE_NAMES.get(user.role, '알수없음'),
        "role_key": ROLE_KEYS.get(user.role, 'unknown'),
    }), 200


@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def me():
    # 헤더에 "로그인 유저명 + 등급" 을 항상 최신 DB 기준으로 보여주기 위한 엔드포인트.
    user = User.query.get(get_jwt_identity())
    if not user:
        return jsonify({"msg": "사용자를 찾을 수 없습니다."}), 404
    return jsonify(user.to_dict()), 200
