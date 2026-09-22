"""GELF 전송 헬퍼 — 게시판(앱)이 보안 로그를 Graylog(SIEM)로 직접 보낸다.

로그인 실패 같은 '앱 계층 사건'은 tcpdump 로 못 잡는다. 앱이 아는 사실(누가·어디서
실패했나)을 GELF 한 줄로 SIEM 에 흘려보내면, 집계·탐지·대응은 Graylog+n8n 이 맡는다.

GELF: JSON 한 줄, 커스텀 필드는 `_` 접두사. UDP 12201(fire-and-forget).
설정: GELF_HOST / GELF_PORT (config). 전송 실패는 로그인 흐름을 막지 않도록 조용히 무시.
"""
import json
import socket

from flask import current_app


def send_gelf(short_message, rule, **fields):
    """GELF 경보를 Graylog 로 보낸다(실패해도 예외를 올리지 않는다)."""
    host = current_app.config.get('GELF_HOST', 'localhost')
    port = int(current_app.config.get('GELF_PORT', 12201))
    msg = {'version': '1.1', 'host': 'board', 'short_message': short_message,
           'level': 4, '_rule': rule}
    for k, v in fields.items():
        msg['_' + k] = v
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.sendto(json.dumps(msg).encode(), (host, port))
        finally:
            s.close()
    except Exception:
        pass   # SIEM 이 꺼져 있어도 로그인 자체는 계속 동작해야 한다
