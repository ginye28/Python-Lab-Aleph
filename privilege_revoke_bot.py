#!/usr/bin/env python3
"""자동 권한 회수봇 — 게시판 관리자 목록을 훑어 허용목록(ADMIN_ALLOWLIST) 밖의
admin(과잉권한)을 찾아 Graylog 로 신고한다(GELF). 표준 라이브러리만 사용.

.env (같은 폴더 또는 _7_board_test/.env) 에서 다음 값을 읽는다:
  BOARD_URL (기본 http://localhost:5000)
  ADMIN_API_KEY (없으면 SECURITY_API_KEY)
  ADMIN_ALLOWLIST (콤마 구분 — 과잉권한 판정에서 제외할 계정)
  GRAYLOG_HOST (기본 localhost), GRAYLOG_GELF_PORT (기본 12201)

사용법:
  python privilege_revoke_bot.py            # 위반 신고(GELF 전송)
  python privilege_revoke_bot.py --dry-run  # 신고 없이 위반만 출력
  python privilege_revoke_bot.py --revoke   # n8n 없이 직접 회수까지 수행
"""
import os
import sys
import json
import socket
import urllib.request
import urllib.error


def _load_env():
    for path in (os.path.join(os.path.dirname(__file__), ".env"),
                 os.path.join(os.path.dirname(__file__), "_7_board_test", ".env")):
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())


def _api_get(url, api_key):
    req = urllib.request.Request(url, headers={"X-API-Key": api_key})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())


def _api_post(url, api_key, body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                  headers={"X-API-Key": api_key, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.status, json.loads(r.read().decode())


def _send_gelf(host, port, short_message, **extra):
    msg = {"version": "1.1", "host": "privilege-revoke-bot", "short_message": short_message, "level": 5}
    for k, v in extra.items():
        msg["_" + k] = v
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.sendto(json.dumps(msg).encode(), (host, port))
    finally:
        s.close()


def main():
    _load_env()
    dry_run = "--dry-run" in sys.argv
    do_revoke = "--revoke" in sys.argv

    board_url = os.environ.get("BOARD_URL", "http://localhost:5000")
    api_key = os.environ.get("ADMIN_API_KEY") or os.environ.get("SECURITY_API_KEY", "")
    allowlist = {u.strip() for u in os.environ.get("ADMIN_ALLOWLIST", "").split(",") if u.strip()}
    graylog_host = os.environ.get("GRAYLOG_HOST", "localhost")
    graylog_port = int(os.environ.get("GRAYLOG_GELF_PORT", "12201"))

    if not api_key:
        print("ADMIN_API_KEY(또는 SECURITY_API_KEY) 가 없습니다. .env 를 확인하세요.", file=sys.stderr)
        sys.exit(2)

    try:
        admins = _api_get(f"{board_url}/api/admin/users?role=admin", api_key)
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        print(f"[privilege_revoke_bot] 게시판 접속 실패: {e}", file=sys.stderr)
        sys.exit(1)

    violations = [u for u in admins if u["username"] not in allowlist]

    if not violations:
        print("[privilege_revoke_bot] 과잉권한 없음 (admin 전원 허용목록 안)")
        return

    for u in violations:
        username = u["username"]
        granted_by = u.get("role_granted_by") or "unknown"
        print(f"[privilege_revoke_bot] 위반 발견: '{username}' has unauthorized admin "
              f"(granted_by={granted_by})")

        if dry_run:
            continue

        _send_gelf(
            graylog_host, graylog_port,
            f"privilege violation: '{username}' has unauthorized admin",
            rule="priv-unauthorized-admin", user=username, granted_by=granted_by,
            src_ip="127.0.0.1",
        )
        print(f"  -> Graylog 로 GELF 신고 전송 ({graylog_host}:{graylog_port})")

        if do_revoke:
            status, resp = _api_post(f"{board_url}/api/admin/revoke", api_key,
                                      {"username": username, "student": "privilege-revoke-bot",
                                       "reason": "자동 회수봇(--revoke) 직접 회수"})
            print(f"  -> 직접 회수 결과: {status} {resp}")


if __name__ == "__main__":
    main()
