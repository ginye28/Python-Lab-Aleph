# 자리 옮길 때 체크리스트

새 PC에서 실습 환경을 다시 세우는 순서입니다. 익숙해지면 5분이면 끝납니다.

---

## 준비물 (항상 들고 다닐 것)

| 항목 | 어디에 보관 | 비고 |
|---|---|---|
| 이 저장소 | git | 코드 + compose + 체크리스트 |
| n8n 워크플로 JSON | git (`workflows/` 폴더) | 비밀값 안 들어가므로 커밋 안전 |
| `.env` | USB / 비밀번호 관리자 | **git 에 올라가지 않음** |
| 텔레그램 봇 토큰 · chat_id | `.env` 와 함께 | 개인 것이어야 함 |

---

## git 으로 오는 것 / 안 오는 것

`git pull` 은 **레시피**를 가져올 뿐 **상태**를 가져오지 않습니다.

| | git 으로 옴 | 따로 챙겨야 함 |
|---|---|---|
| `docker-compose.yml` | O | |
| 워크플로 JSON (노드 구성 · 웹훅 경로) | O | |
| 앱 코드 · `requirements.txt` | O | |
| `.env` (API 키, 암호화 키) | | USB / 비밀번호 관리자 |
| 워크훅 URL · 봇 토큰 | | `.env` 에 보관 (아래 `$env` 방식) |
| MySQL 데이터 | | 볼륨에 있음, 필요하면 `mysqldump` |

그 자리에 원래 있던 n8n 은 쓰지 않습니다. compose 가 `aleph-n8n` 을 새로 띄우므로 어느 자리에서든 컨테이너 이름 · 포트 · 설정이 동일합니다.

---

## 워크플로에서 비밀값 분리하기 (`$env`)

이 저장소는 **public** 입니다. 디스코드·슬랙 Webhook URL 과 텔레그램 봇 토큰은 그 자체가 인증 수단이라, 노드에 하드코딩한 채로 워크플로 JSON 을 커밋하면 그대로 노출됩니다.

그래서 노드에서는 값을 직접 쓰지 않고 환경변수를 참조합니다.

**n8n 노드에서 (URL 필드 우측의 `Fixed` → `Expression` 으로 전환)**

| 노드 | 필드 | 넣을 값 |
|---|---|---|
| 디스코드 | URL | `{{ $env.DISCORD_WEBHOOK_URL }}` |
| 슬랙 | URL | `{{ $env.SLACK_WEBHOOK_URL }}` |
| 텔레그램 | URL | `https://api.telegram.org/bot{{ $env.TELEGRAM_BOT_TOKEN }}/sendMessage` |
| 텔레그램 | Body `chat_id` | `{{ $env.TELEGRAM_CHAT_ID }}` |

실제 값은 `.env` 에만 두고, `docker-compose.yml` 이 n8n 컨테이너로 주입합니다. `.env` 를 고친 뒤에는 컨테이너를 다시 올려야 반영됩니다.

```powershell
docker compose up -d --force-recreate n8n
```

이렇게 하면 워크플로 JSON 에 비밀이 하나도 안 남아서 **그대로 커밋해도 안전**하고, 새 자리에서는 Import 만 하면 URL 까지 전부 복원됩니다.

> 노드 전체를 옮길 때는 파일 없이도 됩니다. n8n 캔버스에서 **Ctrl+A → Ctrl+C**, 새 n8n 에서 **Ctrl+V** 하면 노드 구성이 통째로 붙습니다.

---

## 새 자리에서 (매번)

**1. 저장소 받기**

```powershell
git clone <저장소주소> C:\gov\Python-Lab-Aleph
cd C:\gov\Python-Lab-Aleph
```

**2. `.env` 채우기**

```powershell
copy .env.example .env
notepad .env
```

`N8N_ENCRYPTION_KEY` 는 **처음 만든 값을 계속 재사용**하세요. 이 값이 바뀌면 n8n 자격증명이 복호화되지 않습니다.

**3. 3306 / 5678 포트가 비어있는지 확인**

```powershell
netstat -ano | findstr ":3306 :5678"
```

뭔가 잡고 있으면 그 컨테이너를 먼저 내리세요.

```powershell
docker ps
docker stop <컨테이너이름>
```

**4. 컨테이너 띄우기**

```powershell
docker compose up -d
docker compose ps
```

MySQL 최초 기동은 20~30초 걸립니다. `docker compose logs -f mysql` 로 `ready for connections` 를 확인하세요.

**5. n8n 워크플로 가져오기**

브라우저에서 http://localhost:5678 → 우측 상단 `⋯` → **Import from File** → `workflows/*.json`

**6. 텔레그램 자격증명 넣기**

> 자격증명은 워크플로 JSON 에 들어있지 않습니다. n8n 자체 DB 에 따로 저장되므로 **git 으로 따라오지 않습니다.**
> 워크플로 JSON 에는 "이 자격증명을 쓴다" 는 참조만 있습니다.

방법이 두 가지입니다.

**(a) 손으로 다시 입력 — 가장 간단, 1분**

n8n 에서 Telegram 노드를 열고 Credential 을 새로 만들어 봇 토큰을 붙여넣습니다. 자격증명이 몇 개 안 되면 이게 제일 빠릅니다.

**(b) 암호화된 자격증명 파일을 들고 다니기**

`N8N_ENCRYPTION_KEY` 가 같아야 복호화됩니다. 이 파일은 **git 에 올리지 말고** `.env` 와 같은 곳(USB 등)에 보관하세요.

```powershell
# 떠나는 자리에서 내보내기
docker exec aleph-n8n n8n export:credentials --all --output=/home/node/.n8n/creds.json
docker cp aleph-n8n:/home/node/.n8n/creds.json .\creds.json

# 새 자리에서 가져오기
docker cp .\creds.json aleph-n8n:/home/node/.n8n/creds.json
docker exec aleph-n8n n8n import:credentials --input=/home/node/.n8n/creds.json
docker restart aleph-n8n
```

**봇을 새로 만든 경우에만 추가로:**

- BotFather 에서 본인 봇 생성 (`/newbot`)
- **텔레그램 앱에서 그 봇에게 `/start` 를 먼저 보낼 것** (안 하면 `403 bot can't initiate conversation`)
- 본인 chat_id 확인: `https://api.telegram.org/bot<토큰>/getUpdates` 의 `result[0].message.chat.id`

**7. 워크플로 활성화**

`/webhook/...` (Production URL) 은 워크플로가 **Active** 여야 동작합니다. `/webhook-test/...` 는 편집기에서 "Test workflow" 를 누른 뒤 딱 한 번만 받습니다.

**8. Flask 실행**

```powershell
pip install -r requirements.txt
cd _7_board_test
python app.py
```

터미널 첫 줄에 `키 로드됨 — 앞 4자리:` 가 찍히면 `.env` 가 제대로 읽힌 것입니다.

---

## 자리 뜨기 전에 (매번)

**1. 워크플로 내보내기**

n8n 에서 워크플로 열고 `⋯` → **Download** → `workflows/` 폴더에 저장

**2. 커밋**

```powershell
git add -A
git commit -m "실습 진행 상황 저장"
git push
```

**3. 뒷정리 (선택)**

```powershell
docker compose down          # 컨테이너만 정리, 데이터는 볼륨에 남음
docker compose down -v       # 볼륨까지 삭제 — 남의 자리라면 이쪽
```

---

## 최초 1회: 지금 쓰던 환경에서 넘어오기

지금 돌아가는 `my-mysql`, `n8n` 컨테이너는 compose 가 만드는 것과 **별개**입니다. 그냥 `docker compose up -d` 하면 n8n 이 백지 상태로 뜨니 순서를 지키세요.

### A. 깔끔하게 새로 시작 (권장)

```powershell
# 1) 먼저 n8n 에서 워크플로를 workflows/ 폴더로 Download
# 2) 기존 컨테이너 정지
docker stop n8n my-mysql
# 3) compose 로 새로 띄우기
docker compose up -d
# 4) 워크플로 Import → 텔레그램 자격증명만 다시 입력
```

### B. 기존 n8n 데이터를 그대로 이어쓰기

자격증명까지 살리려면 **기존 암호화 키**를 알아내 `.env` 에 넣어야 합니다.

```powershell
docker exec n8n cat /home/node/.n8n/config
```

출력에서 `encryptionKey` 값을 복사해 `.env` 의 `N8N_ENCRYPTION_KEY` 에 넣고, 기존 볼륨 이름을 확인합니다.

```powershell
docker inspect n8n --format "{{json .Mounts}}"
```

나온 볼륨 이름을 `docker-compose.yml` 의 `n8n_data` 자리에 external 볼륨으로 지정하면 그대로 이어집니다.

---

## 자주 걸리는 것들

| 증상 | 원인 | 해결 |
|---|---|---|
| `Access denied for user 'root'@'172.x.x.x'` | 3306 을 다른 컨테이너가 점유 | `docker ps` 로 확인 후 정지 |
| Ports 칸이 비어있음 | `-p` 없이 만든 컨테이너 | 포트 매핑은 나중에 못 붙임, 재생성 필요 |
| `Unknown database` | app.py 의 DB 이름과 실제 DB 불일치 | `SHOW DATABASES` 로 확인 |
| n8n 200 OK 인데 아무 일도 안 일어남 | `Respond: Immediately` 의 정상 응답 | n8n **Executions** 에서 실제 에러 확인 |
| `SERVICE KEY IS NOT REGISTERED` | Encoding 키 이중 인코딩 | Decoding 키 사용 |
| 텔레그램 `403 can't initiate conversation` | 봇에게 `/start` 를 안 보냄 | 텔레그램에서 봇 열고 Start |
| 텔레그램 `400 chat not found` | 물려받은 남의 chat_id | `getUpdates` 로 본인 chat_id 확인 |
