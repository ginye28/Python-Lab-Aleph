"""과제 1 — 로그인 경보를 n8n Webhook 으로 보내는 전송기.

n8n 워크플로(workflows/security-alert-bot.json)를 Import 해서 Active 로 켜둔 뒤 실행한다.
n8n 화면에서 Webhook 노드를 열면 실제 URL(Production URL)을 볼 수 있다.
"""
import os
import sys

import requests
from dotenv import load_dotenv

load_dotenv()  # 상위 폴더의 .env

# ── 코드 맨 위 상수 ──────────────────────────────────────
STUDENT_NAME = os.environ.get("STUDENT_NAME", "본인이름으로_바꾸세요")
N8N_WEBHOOK_URL = os.environ.get(
    "SECURITY_WEBHOOK_URL",
    "http://localhost:5678/webhook/security-events",
)

# 거부(레벨 10 이상)와 허용(레벨 10 미만)이 최소 1건씩 섞이도록 구성한다.
ALERTS = [
    {"ip": "203.0.113.114", "level": 10, "rule": "5712", "fail_count": 5},  # → 거부 예상
    {"ip": "192.168.0.10",  "level": 3,  "rule": "5501", "fail_count": 1},  # → 허용 예상
]


def send_alerts():
    payload = {"student": STUDENT_NAME, "alerts": ALERTS}
    try:
        res = requests.post(N8N_WEBHOOK_URL, json=payload, timeout=10)
        print(f"[n8n] POST {N8N_WEBHOOK_URL} -> {res.status_code}")
        print(res.text[:300])
        return res.status_code == 200
    except requests.RequestException as e:
        # 과제 요구사항: 전송 실패해도 프로그램이 죽지 않고 오류 메시지를 출력한다
        print(f"[오류] n8n 으로 전송하지 못했습니다: {e}", file=sys.stderr)
        return False


if __name__ == "__main__":
    ok = send_alerts()
    sys.exit(0 if ok else 1)
