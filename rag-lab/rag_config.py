# rag_config.py — RAG 공통 설정 (save_docs.py / ask.py / answer.py 가 함께 사용)
import os
import chromadb
from chromadb.utils import embedding_functions

# ① 영구 저장: 메모리가 아니라 ragdb 폴더에 저장 → 프로그램을 꺼도 데이터가 남는다 (R1)
#    32번 문서에서 배운 '절대경로 습관' — 어느 폴더에서 실행해도 항상 같은 ragdb를 쓰게 한다
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
client = chromadb.PersistentClient(path=os.path.join(BASE_DIR, "ragdb"))

# ② 임베딩 모델: 한국어를 이해하는 다국어 모델 (최초 1회 자동 다운로드, 약 500MB)
embed_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
    model_name="paraphrase-multilingual-MiniLM-L12-v2"
)

# 컬렉션 = 문서들을 담는 바구니 (엑셀 파일 속 '시트 하나' 느낌). 없으면 만들고 있으면 가져온다
collection = client.get_or_create_collection(name="security_faq", embedding_function=embed_fn)
