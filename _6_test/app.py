from datetime import datetime
import json
from flask import Flask, Response, render_template_string
import pymysql
import requests

app = Flask(__name__)

# DB 연결 설정 (root / 123456)
DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "123456",
    "charset": "utf8mb4",
    "cursorclass": pymysql.cursors.DictCursor,
}


def init_db():
  """데이터베이스 및 테이블 자동 생성"""
  conn = pymysql.connect(
      host=DB_CONFIG["host"], user=DB_CONFIG["user"], password=DB_CONFIG["password"]
  )
  try:
    with conn.cursor() as cursor:
      cursor.execute("CREATE DATABASE IF NOT EXISTS github_db;")
      cursor.execute("USE github_db;")
      cursor.execute("""
                CREATE TABLE IF NOT EXISTS api_responses (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    current_user_url VARCHAR(255),
                    authorizations_url VARCHAR(255),
                    code_search_url VARCHAR(255),
                    fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
    conn.commit()
  finally:
    conn.close()


@app.route("/")
def index():
  init_db()

  # 1. GitHub API 호출 및 데이터 수집
  r = requests.get("https://api.github.com")
  data = r.json()

  # 2. MySQL에 데이터 저장
  conn = pymysql.connect(
      host=DB_CONFIG["host"],
      user=DB_CONFIG["user"],
      password=DB_CONFIG["password"],
      database="github_db",
      charset=DB_CONFIG["charset"],
      cursorclass=DB_CONFIG["cursorclass"],
  )
  try:
    with conn.cursor() as cursor:
      sql = """
                INSERT INTO api_responses (current_user_url, authorizations_url, code_search_url) 
                VALUES (%s, %s, %s)
            """
      cursor.execute(
          sql,
          (
              data.get("current_user_url"),
              data.get("authorizations_url"),
              data.get("code_search_url"),
          ),
      )
    conn.commit()
  finally:
    conn.close()

  return "데이터가 성공적으로 수집 및 저장되었습니다! <br><a href='/view'>웹으로 보기</a> | <a href='/download'>파일로 다운로드</a>"


@app.route("/view")
def view_data():
  """저장된 내용을 간단한 웹 화면으로 출력"""
  conn = pymysql.connect(
      host=DB_CONFIG["host"],
      user=DB_CONFIG["user"],
      password=DB_CONFIG["password"],
      database="github_db",
      charset=DB_CONFIG["charset"],
      cursorclass=DB_CONFIG["cursorclass"],
  )
  try:
    with conn.cursor() as cursor:
      cursor.execute("SELECT * FROM api_responses ORDER BY id DESC")
      rows = cursor.fetchall()
  finally:
      conn.close()

  html = """
    <h2>GitHub API 응답 데이터 목록</h2>
    <table border="1" cellpadding="5" cellspacing="0">
        <tr>
            <th>ID</th><th>Current User URL</th><th>Authorizations URL</th><th>Code Search URL</th><th>Fetched At</th>
        </tr>
        {% for row in rows %}
        <tr>
            <td>{{ row.id }}</td>
            <td>{{ row.current_user_url }}</td>
            <td>{{ row.authorizations_url }}</td>
            <td>{{ row.code_search_url }}</td>
            <td>{{ row.fetched_at }}</td>
        </tr>
        {% endfor %}
    </table>
    <br><a href="/">데이터 새로 수집하기</a>
    """
  return render_template_string(html, rows=rows)


@app.route("/download")
def download_file():
  """저장된 내용을 파일 형식(JSON)으로 출력 및 다운로드"""
  conn = pymysql.connect(
      host=DB_CONFIG["host"],
      user=DB_CONFIG["user"],
      password=DB_CONFIG["password"],
      database="github_db",
      charset=DB_CONFIG["charset"],
      cursorclass=DB_CONFIG["cursorclass"],
  )
  try:
    with conn.cursor() as cursor:
      cursor.execute("SELECT * FROM api_responses")
      rows = cursor.fetchall()
  finally:
    conn.close()

  # datetime 객체 JSON 직렬화 오류 방지 변환
  for row in rows:
    if "fetched_at" in row and isinstance(row["fetched_at"], datetime):
      row["fetched_at"] = row["fetched_at"].strftime("%Y-%m-%d %H:%M:%S")

  json_data = json.dumps(rows, ensure_ascii=False, indent=4)

  return Response(
      json_data,
      mimetype="application/json",
      headers={"Content-Disposition": "attachment;filename=github_data.json"},
  )


if __name__ == "__main__":
  app.run(debug=True, port=5000)