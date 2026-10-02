# Wazuh 브루트포스 알림이 Graylog·n8n으로 안 넘어간 문제 (트러블슈팅)

> 날짜: 2026-10-02 · 결과: **해결** (Graylog Alert 발생 → n8n 7번 실행 → 디스코드 알림 수신)

## 1. 증상

- Postman으로 로그인 실패 요청을 8번 보내 IP가 차단되면, Graylog Alerts에 Wazuh 브루트포스 알림이 뜨고 n8n으로 넘어가야 한다.
- 실제로는 Graylog Alerts에 `7-Wazuh 브루트포스 탐지 (rule 100211)`이 안 뜨고, n8n Executions에도 새 실행이 없었다.
- 헷갈린 점: Graylog Alerts에는 `3-IP 반복 로그인 실패 탐지`가 이미 떠 있었다. 이건 **다른 경로**의 알림이다.

## 2. 전체 흐름 (두 갈래)

| 구분 | 경로 | n8n 웹훅 | 받는 워크플로 |
|---|---|---|---|
| A. Wazuh 경로 (이번 테스트) | Flask seclog → Wazuh `100210`/`100211` → Graylog `7-Wazuh 브루트포스 탐지` → n8n | `/webhook/wazuh-alert` | `7-Wazuh 경보봇(Graylog 연동)` — **Published** |
| B. GELF 경로 | Flask GELF(`rule=login-bruteforce`) → Graylog `3-IP 반복 로그인 실패 탐지` → n8n | `/webhook/ip-block` | `4-IP 차단봇(Graylog 연동)` — 미발행 |

- 이번 테스트는 **A 경로**다. 7번 워크플로만 Publish된 상태가 정상이다.
- n8n 운영 웹훅(`/webhook/...`)은 워크플로가 **Publish**돼야 동작한다. 미발행이면 404.

## 3. 원인

**앱의 자동 차단이 Wazuh 탐지보다 먼저 걸렸다.**

- Wazuh 규칙 `100211`: 같은 IP의 `login_failed` **6회**(120초 이내)가 있어야 발동.
  ```xml
  <rule id="100211" level="10" frequency="6" timeframe="120">
    <if_matched_sid>100210</if_matched_sid>
    <same_source_ip />
  ```
- Flask 로그인: 연속 실패 **5회**(`LOGIN_FAIL_THRESHOLD` 기본값)에서 IP 차단. 6번째 요청부터는 `block_ip_guard`(before_request)가 로그인 로직 **앞에서** 403으로 끊는다.
- 그 결과 seclog에는 `login_failed`가 5줄까지만 쌓여, Wazuh가 6회를 못 채우고 `100211`이 한 번도 발동하지 않았다.

### 확인 근거

- Graylog에는 Wazuh `100210`(로그인 실패 1건)만 테스트마다 5건씩 들어오고, `100211`은 0건.
- Graylog 이벤트 `7-Wazuh 브루트포스 탐지 (rule 100211)`의 `Last Matched`가 `Never`.
- n8n Executions 마지막 실행이 14:04(웹셸 규칙 `100220`)에서 끊김.

## 4. 해결

`.env`에 앱 차단 임계값을 Wazuh보다 높게 설정하고 Flask를 재시작.

```env
LOGIN_FAIL_THRESHOLD=10
```

- 설정 위치: `_8_cafe_rbac_test/.env` (config.py의 `LOGIN_FAIL_THRESHOLD`가 읽음, 기본 5)
- 순서가 핵심: **Wazuh 6회 < 앱 차단 10회** → Wazuh가 먼저 탐지하고, n8n 7번이 IP 차단, 앱은 10번째에 자체 차단.
- `.env`는 UTF-8로 저장해야 한다(한글 주석을 ANSI로 쓰면 python-dotenv가 깨짐).

### 대안

- Wazuh `local_rules.xml`의 `frequency="6"`을 `4`로 낮추고 manager 재시작 (앱 설정은 그대로).

## 5. 검증 결과 (15:31~15:32)

1. 앱: 8번 이상 로그인 실패 → `3-IP` Alert `count()=8.0`
2. Graylog: `7-Wazuh 브루트포스 탐지 (rule 100211)` Alert **최초 발생** (15:32:01)
3. n8n: `7-Wazuh 경보봇(Graylog 연동)` 실행 Succeeded (15:32:09, 2.2s)
4. 디스코드: `[Wazuh 100211] 연습 웹앱 브루트포스 의심 ... 대응: IP 차단 + 인시던트 #7` 수신

## 6. 재테스트 체크리스트

1. 차단된 IP 해제 — Postman `IP차단-6 차단 해제` (서버 재시작해도 차단 목록은 DB에 남아 있음)
2. 같은 IP로 로그인 실패 8번 이상 전송 (6번째 실패 근처에서 Wazuh 발동)
3. 1~2분 내 Graylog Alerts에 `7-Wazuh 브루트포스 탐지` 확인 (이벤트가 1분마다 실행됨)
4. n8n Executions에 `7-Wazuh 경보봇` 새 실행 확인
5. 디스코드/슬랙/텔레그램 알림 확인

## 7. 배운 점 / 주의

- **탐지 계층의 임계값 순서**: 앱 차단 임계값이 탐지 규칙보다 낮으면, 차단 후 로그가 끊겨 탐지가 영원히 안 걸린다. 탐지 규칙 < 앱 차단.
- **알림이 "있다"와 "n8n에 간다"는 별개**: Graylog Alert이 떠도 알림 대상 웹훅이 가리키는 워크플로가 미발행이면 n8n에는 아무것도 안 온다.
- **경로 구분**: GELF 경로(`ip-block`)와 Wazuh 경로(`wazuh-alert`)는 다른 워크플로를 쓴다. 어떤 경로를 테스트하는지 먼저 정하고, 그 경로의 워크플로만 Publish.
- **반복 Alert**: `3-IP`는 15초마다 최근 1분을 재검색해서 같은 IP Alert이 반복된다(그레이스 기간 1분 후 멈춤). 정상 동작.
- n8n Webhook 노드의 Test URL(`/webhook-test/...`)은 "Listen for test event" 중에만 동작하고, Production URL(`/webhook/...`)은 Publish 후에만 동작한다.
