#!/usr/bin/env python3
# Suricata eve.json alert 를 GELF 로 Graylog 에 전달 (오프라인 분석 결과 포워딩)
import sys, json, socket

def send_gelf(host, port, msg):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.sendto(json.dumps(msg).encode(), (host, port))
    finally:
        s.close()

def main():
    eve_path = sys.argv[1]
    graylog_host = sys.argv[2] if len(sys.argv) > 2 else "gl-graylog"
    graylog_port = int(sys.argv[3]) if len(sys.argv) > 3 else 12201
    n = 0
    for line in open(eve_path):
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        if d.get("event_type") != "alert":
            continue
        alert = d["alert"]
        gelf = {
            "version": "1.1", "host": "suricata",
            "short_message": alert.get("signature", "suricata alert"),
            "level": 5,
            "_rule": "ids-alert",
            "_src_ip": d.get("src_ip", ""),
            "_dest_ip": d.get("dest_ip", ""),
            "_signature": alert.get("signature", ""),
            "_category": alert.get("category", ""),
            "_severity": alert.get("severity", 0),
        }
        send_gelf(graylog_host, graylog_port, gelf)
        n += 1
    print(f"forwarded {n} alerts to {graylog_host}:{graylog_port}")

if __name__ == "__main__":
    main()
