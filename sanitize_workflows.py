#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""n8n 워크플로 JSON 에 박힌 비밀값을 {{ $env.이름 }} 참조로 바꾼다.

n8n 화면에서 노드의 URL 칸을 Expression 이 아니라 값으로 입력한 채 Export 하면,
웹훅 URL·봇 토큰이 JSON 에 원문 그대로 들어간다. 그대로 커밋하면 GitHub 의
push protection 에 막히고(막히지 않으면 더 나쁘다) 비밀값을 재발급해야 한다.
커밋 전에 이 스크립트를 한 번 돌리면 그런 값들을 전부 걸러낸다.

찾는 방법 두 가지
  1) 알려진 형태  — 슬랙/디스코드 웹훅 URL, 텔레그램 봇 토큰
  2) .env 대조   — .env 에 들어 있는 16자 이상의 값이 JSON 안에 그대로 있으면
                   그 키 이름으로 바꾼다. API 키처럼 형태만으로는 못 찾는 값을 잡는다.

사용:
  python sanitize_workflows.py            # 검사 + 치환 (기본 대상: workflows 폴더들)
  python sanitize_workflows.py --check    # 치환 없이 검사만. 발견되면 종료코드 1
  python sanitize_workflows.py 파일.json   # 대상 직접 지정 (파일/폴더 여러 개 가능)

커밋할 때마다 자동으로 검사하려면 .git/hooks/pre-commit 에 아래 두 줄을 넣는다.
  #!/bin/sh
  python sanitize_workflows.py --check || exit 1
"""
import argparse
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

# 기본 검사 대상 — 저장소 안의 워크플로 폴더들
DEFAULT_TARGETS = [
    os.path.join(HERE, 'workflows'),
    os.path.join(HERE, '_8_cafe_rbac_test', 'workflows'),
]

# .env 를 찾을 위치 (있는 것만 읽는다)
ENV_PATHS = [
    os.path.join(HERE, '.env'),
    os.path.join(HERE, '_8_cafe_rbac_test', '.env'),
]

# .env 값이 이 길이 이상일 때만 대조한다. 짧은 값(예: 비밀번호 123456)까지 바꾸면
# 무관한 숫자까지 건드려서 워크플로가 망가진다.
MIN_ENV_VALUE_LEN = 16

# (이름, 찾을 정규식, 바꿀 문자열)
# JSON 문자열 통째로 잡아서 바꾸므로 앞의 '=' (n8n Expression 표시)도 함께 붙인다.
PATTERNS = [
    (
        '슬랙 웹훅 URL',
        re.compile(r'"=?https://hooks\.slack\.com/services/[^"]*"'),
        '"={{ $env.SLACK_WEBHOOK_URL }}"',
    ),
    (
        '디스코드 웹훅 URL',
        re.compile(r'"=?https://(?:discord|discordapp)\.com/api/webhooks/[^"]*"'),
        '"={{ $env.DISCORD_WEBHOOK_URL }}"',
    ),
    (
        '텔레그램 봇 토큰',
        # 뒤의 /sendMessage 같은 경로는 그대로 두고 토큰 부분만 바꾼다.
        re.compile(r'"=?https://api\.telegram\.org/bot[0-9]+:AA[A-Za-z0-9_-]+'),
        '"=https://api.telegram.org/bot{{ $env.TELEGRAM_BOT_TOKEN }}',
    ),
]


def mask(value):
    """비밀값을 화면에 그대로 찍지 않는다. 어디를 고쳤는지 알아볼 만큼만 남긴다."""
    if len(value) <= 12:
        return value[:2] + '…'
    return value[:10] + '…(' + str(len(value)) + '자)'


def load_env_secrets():
    """.env 에서 대조할 만한 값들을 읽는다. {값: 키이름} 형태."""
    secrets = {}
    for path in ENV_PATHS:
        if not os.path.exists(path):
            continue
        with open(path, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, value = line.split('=', 1)
                key, value = key.strip(), value.strip().strip('"').strip("'")
                if len(value) >= MIN_ENV_VALUE_LEN:
                    secrets[value] = key
    return secrets


def line_of(text, index):
    return text.count('\n', 0, index) + 1


def sanitize(text, env_secrets):
    """치환된 본문과 [(줄번호, 종류, 마스킹된 값)] 목록을 돌려준다."""
    findings = []

    for label, pattern, replacement in PATTERNS:
        for m in list(pattern.finditer(text)):
            findings.append((line_of(text, m.start()), label, mask(m.group(0).strip('"'))))
        text = pattern.sub(replacement, text)

    # 긴 값부터 바꿔야 짧은 값이 긴 값의 일부를 먼저 갉아먹지 않는다.
    for value in sorted(env_secrets, key=len, reverse=True):
        key = env_secrets[value]
        # 값을 품고 있는 JSON 문자열 전체를 잡아, 값 자리만 $env 참조로 바꾸고
        # Expression 표시(=)를 앞에 붙인다.
        pattern = re.compile(r'"=?([^"]*)' + re.escape(value) + r'([^"]*)"')
        for m in list(pattern.finditer(text)):
            findings.append((line_of(text, m.start()), f'.env 의 {key}', mask(value)))
        text = pattern.sub(lambda m: f'"={m.group(1)}{{{{ $env.{key} }}}}{m.group(2)}"', text)

    findings.sort()
    return text, findings


def collect_files(targets):
    files = []
    for t in targets:
        if os.path.isdir(t):
            for name in sorted(os.listdir(t)):
                if name.endswith('.json'):
                    files.append(os.path.join(t, name))
        elif os.path.isfile(t):
            files.append(t)
    return files


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('targets', nargs='*', help='검사할 파일/폴더 (생략 시 workflows 폴더들)')
    ap.add_argument('--check', action='store_true', help='치환하지 않고 검사만 (발견 시 종료코드 1)')
    args = ap.parse_args()

    files = collect_files(args.targets or DEFAULT_TARGETS)
    if not files:
        print('[!] 검사할 JSON 파일이 없습니다.')
        return 0

    env_secrets = load_env_secrets()
    if not env_secrets:
        print('[알림] .env 를 못 찾았습니다. 알려진 형태(슬랙/디스코드/텔레그램)만 검사합니다.')

    total = 0
    for path in files:
        with open(path, encoding='utf-8') as f:
            original = f.read()

        cleaned, findings = sanitize(original, env_secrets)
        if not findings:
            continue

        total += len(findings)
        rel = os.path.relpath(path, HERE)
        print(f"\n[!] {rel}")
        for line, label, masked in findings:
            print(f"    {line:>4}행  {label}: {masked}")

        if args.check:
            continue

        with open(path, 'w', encoding='utf-8', newline='') as f:
            f.write(cleaned)
        print(f"    -> {len(findings)}건을 $env 참조로 바꿨습니다.")

    if total == 0:
        print(f"[OK] 비밀값 없음 (검사한 파일 {len(files)}개)")
        return 0

    if args.check:
        print(f"\n[중단] 비밀값 {total}건이 남아 있습니다. 치환하려면 --check 없이 실행하세요.")
        return 1

    print(f"\n[완료] 총 {total}건 치환. 바뀐 값들은 .env 에 있어야 n8n 이 읽습니다.")
    print("       .env 를 고쳤다면 'docker compose up -d' 로 컨테이너를 재생성하세요.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
