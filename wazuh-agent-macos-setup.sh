#!/bin/bash
# macOS Wazuh 에이전트 설치 · 등록 · 설정 (129 수업 대체 스크립트)
# 이 Mac은 Apple Silicon이지만, 공식 macOS 에이전트는 intel64 pkg만 배포되며
# Rosetta로 정상 동작합니다 (Rosetta 미설치 시 설치가 자동으로 안내합니다).
#
# 사용법: chmod +x wazuh-agent-macos-setup.sh && sudo ./wazuh-agent-macos-setup.sh
set -e

PKG_URL="https://packages.wazuh.com/4.x/macos/wazuh-agent-4.9.0-1.intel64.pkg"
PKG_PATH="/tmp/wazuh-agent.pkg"
MANAGER_IP="127.0.0.1"   # 매니저가 Docker로 이 Mac에서 돌고 있고 1514/1515가 호스트에 publish 되어 있음
AGENT_ID="001"
BOARD_ROOT="$HOME/Python-Lab-Aleph/_7_board_test"

# 에이전트 키는 하드코딩하지 않고, 로컬 Docker 의 매니저에서 그때그때 꺼낸다
# (키는 비밀값이라 깃에 올리면 안 된다 — 이 매니저는 이 Mac 에서만 접근 가능)
echo "== 0. 매니저에서 에이전트 키 추출 (agent $AGENT_ID) =="
AGENT_KEY=$(docker exec wazuh-manager bash -c "printf 'E\n${AGENT_ID}\n' | /var/ossec/bin/manage_agents" \
  | awk '/Agent key information/{getline; print; exit}' | tr -d ' \r\n')
if [ -z "$AGENT_KEY" ]; then
  echo "에이전트 키를 가져오지 못했습니다. wazuh-manager 컨테이너가 떠 있는지, agent $AGENT_ID 가 등록돼 있는지 확인하세요." >&2
  exit 1
fi

echo "== 1. 패키지 다운로드 =="
curl -sL -o "$PKG_PATH" "$PKG_URL"

echo "== 2. 설치 (관리자 암호 필요) =="
installer -pkg "$PKG_PATH" -target /

echo "== 3. 매니저 키 등록 =="
/Library/Ossec/bin/manage_agents -i "$AGENT_KEY" <<< $'\n'

echo "== 4. ossec.conf 설정 (매니저 주소 + 로그 감시 + FIM) =="
CONF=/Library/Ossec/etc/ossec.conf
python3 - "$CONF" "$MANAGER_IP" "$BOARD_ROOT" <<'PYEOF'
import sys, re
conf_path, manager_ip, board_root = sys.argv[1], sys.argv[2], sys.argv[3]
c = open(conf_path).read()

# 매니저 주소 설정
c = re.sub(r"<address>.*?</address>", f"<address>{manager_ip}</address>", c, count=1)

# security.log 감시 + templates FIM 추가
extra = f"""  <localfile>
    <log_format>syslog</log_format>
    <location>{board_root}/logs/security.log</location>
  </localfile>

  <syscheck>
    <directories realtime="yes">{board_root}/templates</directories>
  </syscheck>

"""
if "security.log" not in c:
    c = c.replace("</ossec_config>", extra + "</ossec_config>", 1)

open(conf_path, "w").write(c)
print("ossec.conf 업데이트 완료")
PYEOF

echo "== 5. 에이전트 시작 =="
/Library/Ossec/bin/wazuh-control start

echo "== 완료 =="
echo "상태 확인: sudo /Library/Ossec/bin/wazuh-control status"
echo "로그 확인: sudo tail -f /Library/Ossec/logs/ossec.log"
echo "매니저에서 연결 확인: docker exec wazuh-manager /var/ossec/bin/agent_control -l"
