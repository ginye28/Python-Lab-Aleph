# answer.py — 근거 첨부 답변 + 폴백 (R4)
from rag_config import collection

THRESHOLD = 0.7   # 이 거리보다 멀면 "관련 규정 없음"으로 판단 (실험으로 §7에서 조정)

print("보안 FAQ 봇입니다. 빈 입력(Enter)이면 종료.")
while True:
    question = input("\n질문: ")
    if question == "":
        break

    result = collection.query(query_texts=[question], n_results=3)
    docs  = result["documents"][0]
    metas = result["metadatas"][0]
    dists = result["distances"][0]

    if dists[0] > THRESHOLD:                       # 1위조차 멀다 = 규정에 없는 질문
        print("→ 관련 규정을 찾지 못했습니다. 보안팀(내선 1234)에 직접 문의하세요.")
        continue

    print(f"→ {docs[0]}")                          # 가장 가까운 규정 원문으로 답변
    print(f"   (근거: {metas[0]['source']}, 거리 {dists[0]:.3f})")
    others = [m["source"] for m, d in zip(metas[1:], dists[1:]) if d <= THRESHOLD]
    if others:
        print(f"   함께 볼 규정: {', '.join(others)}")
