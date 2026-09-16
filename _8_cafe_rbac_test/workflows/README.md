# n8n 워크플로

n8n에서 만든 워크플로 두 개를 내보낸 것입니다. **두 파일 모두 비밀값이 원문으로 들어있지 않습니다** — 웹훅 URL·봇 토큰은 전부 `{{ $env.이름 }}` 으로만 참조합니다.

| 파일 | 워크플로 | 노드 | 설명 |
| --- | --- | --- | --- |
| `security-alert-bot.json` | 실습과제 - 경보 자동화 봇 | 9개 | **이번 과제 결과물.** 판정 → 분기 → 메신저 3곳 + 게시판 DB 저장 |
| `alert-fanout.json` | 경보 팬아웃 (Discord / Slack / Telegram) | 6개 | 이전 수업에서 만든 연습용. 심각도만 매겨 메신저 3곳으로 보내는 단순 버전 |

## 불러오는 방법

1. `http://localhost:5678` 접속
2. 좌상단 **Create Workflow** → `⋯` 메뉴 → **Import from File…** → 위 JSON 선택
3. 저장한 뒤 우상단 **Publish**

> ⚠️ n8n 2.x는 draft와 published가 분리돼 있습니다. 저장만 하면 production Webhook에는 반영되지 않으니 **Publish**까지 눌러야 합니다.

## 비밀값이 들어가는 자리

노드의 URL 칸을 **Expression 모드**로 바꾼 뒤 아래처럼 참조합니다. 실제 값은 프로젝트 루트 `.env` 에 두고 `docker-compose.yml` 이 n8n 컨테이너의 환경변수로 넘겨 줍니다.

| 노드 | 넣는 값 |
| --- | --- |
| 슬랙 URL | `{{ $env.SLACK_WEBHOOK_URL }}` |
| 디스코드 URL | `{{ $env.DISCORD_WEBHOOK_URL }}` |
| 텔레그램 URL | `https://api.telegram.org/bot{{ $env.TELEGRAM_BOT_TOKEN }}/sendMessage` |
| 텔레그램 chat_id | `{{ $env.TELEGRAM_CHAT_ID }}` |
| 게시판 저장 헤더 `X-API-Key` | `{{ $env.SECURITY_API_KEY }}` |

`.env` 값을 바꾼 뒤에는 컨테이너를 **재생성**해야 새 값이 들어갑니다. 단순 `restart` 로는 반영되지 않습니다.

```bash
docker compose up -d
```

## 게시판 저장 노드 주소

n8n은 컨테이너 안에 있고 게시판은 호스트(내 PC)에서 돕니다. 컨테이너 안에서 `localhost` 는 컨테이너 자기 자신이므로 호스트를 가리키는 주소를 써야 합니다.

```
POST http://host.docker.internal:5000/api/security/events
```
