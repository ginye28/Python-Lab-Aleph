# detect.py  — 경보 분류 스크립트
alerts = [
    {"level": 12, "ip": "1.1.1.1"},
    {"level": 9,  "ip": "2.2.2.2"},
    {"level": 5,  "ip": "3.3.3.3"},
]

def severity(level):
    if level >= 10: return "High"
    if level >= 7:  return "Medium"
    return "Low"

for a in alerts:
    print(f'{a["ip"]} → {severity(a["level"])}')