#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""자동 권한 회수봇 — 과잉권한(admin) 탐지 → Graylog(GELF) 신고.

동작(최소권한 감사)
  1) 게시판 GET /api/admin/users 로 회원·역할을 읽는다(X-API-Key).
  2) role == 'admin' 인데 허용목록(ADMIN_ALLOWLIST) 에 없는 계정 = '과잉권한' 위반.
  3) 위반 1건마다 Graylog 로 GELF 경보를 보낸다(rule=priv-unauthorized-admin).
  4) 이후 Graylog 이벤트 → n8n 이 /api/admin/revoke 를 호출해 '실제 회수'를 한다.
     (이 봇은 '탐지·신고'만 — SOAR 대응은 n8n 이 담당. --revoke 로 직접 회수도 가능.)

윈도우 작업 스케줄러로 매시간 실행할 예정. 표준 라이브러리만 사용(설치 불필요).
비밀값은 코드에 두지 않고 같은 폴더 .env 또는 환경변수에서 읽는다.

사용:
  python privilege_revoke_bot.py            # 탐지 + Graylog 신고
  python privilege_revoke_bot.py --dry-run  # 신고 없이 위반만 출력
  python privilege_revoke_bot.py --revoke    # (대체) 게시판 API 로 직접 회수까지
"""
import argparse
import json
import os
import socket
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))


def load_env():
  """같은 폴더 .env 를 읽어 os.environ 에 채운다(이미 있으면 유지). 의존성 없음."""
  path = os.path.join(HERE, '.env')
  if os.path.exists(path):
    with open(path, encoding='utf-8') as f:
      for line in f:
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
          continue
        k, v = line.split('=', 1)
        os.environ.setdefault(k.strip(), v.strip())


def cfg():
  load_env()
  allow = [u.strip() for u in os.environ.get('ADMIN_ALLOWLIST', '').split(',') if u.strip()]
  return {
      'board': os.environ.get('BOARD_URL', 'http://localhost:5000').rstrip('/'),
      'key': os.environ.get('ADMIN_API_KEY', '') or os.environ.get('SECURITY_API_KEY', ''),
      'allow': allow,
      'graylog_host': os.environ.get('GRAYLOG_HOST', 'localhost'),
      'graylog_port': int(os.environ.get('GRAYLOG_PORT', '12201')),
      'student': os.environ.get('STUDENT', 'lsy'),
      'src_ip': os.environ.get('BOARD_SRC_IP', '127.0.0.1'),  # 신고에 남길 대표 IP
  }


def get_json(url, key=None, method='GET', body=None):
  data = json.dumps(body).encode() if body is not None else None
  req = urllib.request.Request(url, data=data, method=method)
  req.add_header('Content-Type', 'application/json')
  if key:
    req.add_header('X-API-Key', key)
  with urllib.request.urlopen(req, timeout=10) as r:
    return json.loads(r.read().decode())


def find_violations(c):
  """허용목록 밖 admin 목록을 게시판에서 가져온다."""
  d = get_json(f"{c['board']}/api/admin/users?role=admin", key=c['key'])
  return [u for u in d.get('users', []) if u['username'] not in c['allow']]


def send_gelf(c, user):
  """위반 1건을 Graylog GELF(UDP 12201)로 신고."""
  msg = {
      'version': '1.1', 'host': socket.gethostname(),
      'short_message': f"privilege violation: '{user['username']}' has unauthorized admin",
      'level': 4,
      '_rule': 'priv-unauthorized-admin',
      '_user': user['username'],
      '_granted_by': user.get('role_granted_by') or 'unknown',
      '_src_ip': c['src_ip'],
      '_student': c['student'],
      '_count': 1,
  }
  payload = json.dumps(msg).encode()
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  try:
    s.sendto(payload, (c['graylog_host'], c['graylog_port']))
  finally:
    s.close()


def main():
  ap = argparse.ArgumentParser()
  ap.add_argument('--dry-run', action='store_true', help='신고 없이 위반만 출력')
  ap.add_argument('--revoke', action='store_true', help='게시판 API 로 직접 회수까지(대체 경로)')
  args = ap.parse_args()

  c = cfg()
  if not c['key']:
    print('[!] ADMIN_API_KEY(또는 SECURITY_API_KEY) 가 비어 있습니다. .env 확인.')
    sys.exit(2)

  try:
    bad = find_violations(c)
  except Exception as e:
    print(f'[!] 게시판 조회 실패: {e}')
    sys.exit(1)

  if not bad:
    print(f"[OK] 과잉권한 위반 없음 (허용목록: {c['allow'] or '(비어있음=모든 admin이 위반)'})")
    return

  print(f"[!] 과잉권한 admin {len(bad)}건 탐지: " + ', '.join(u['username'] for u in bad))
  for u in bad:
    if args.dry_run:
      print(f"    - {u['username']} (부여자 {u.get('role_granted_by')}) [dry-run]")
      continue
    send_gelf(c, u)
    print(f"    - {u['username']} → Graylog 신고(rule=priv-unauthorized-admin)")
    if args.revoke:  # 대체: n8n 없이 봇이 직접 회수
      r = get_json(f"{c['board']}/api/admin/revoke", key=c['key'], method='POST',
                   body={'username': u['username'], 'student': c['student'],
                         'reason': f"봇 직접 회수: 허용목록 밖 admin ({u['username']})",
                         'src_ip': c['src_ip'], 'source': 'privilege-guard-bot'})
      print(f"      회수: {r.get('old_role')}→{r.get('new_role')} (event {r.get('event_id')})")


if __name__ == '__main__':
  main()
