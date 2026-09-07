from rag_config import collection
question = input("질문: ")
result = collection.query(query_texts=[question], n_results=3)   # 가까운 3건
docs, metas, dists = result["documents"][0], result["metadatas"][0], result["distances"][0]
for rank, (doc, meta, dist) in enumerate(zip(docs, metas, dists), start=1):
    print(f"[{rank}위] 거리 {dist:.3f} | {meta['source']}")
    print(f"      {doc}")