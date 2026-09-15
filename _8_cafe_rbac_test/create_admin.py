"""관리자 계정 복구용 스크립트.

DB 가 초기화(볼륨 삭제 등)되어 admin 계정이 사라졌을 때, 관리자(role=2) 계정을
하나 새로 만들거나 기존 계정을 관리자로 승격시킨다. app.py 와 동일한 DB 접속
정보(.env)를 사용하므로, 같은 폴더(또는 상위 폴더)에 .env 가 있는 상태에서
MySQL 컨테이너가 떠 있어야 한다.

비밀번호를 코드/커밋에 남기지 않기 위해, --password 를 주지 않으면 실행할 때마다
무작위로 생성해서 터미널에 한 번만 출력한다. 그 값을 바로 적어두고 로그인한 뒤
비밀번호를 바꾸는 것을 권장한다.

사용법:
    python create_admin.py                       # username=admin, 비밀번호 자동 생성
    python create_admin.py --username admin --password '직접지정할비번'
"""
import argparse
import os
import secrets

from dotenv import load_dotenv
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

load_dotenv()

ROLE_ADMIN = 2

DB_USER = os.environ.get("MYSQL_USER", "root")
DB_PASSWORD = os.environ.get("MYSQL_ROOT_PASSWORD", "")
DB_HOST = os.environ.get("MYSQL_HOST", "127.0.0.1")
DB_PORT = os.environ.get("MYSQL_PORT", "3306")
DB_NAME = os.environ.get("MYSQL_DATABASE", "github_db")

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = 'cafe_users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Integer, nullable=False, default=0)


def main():
    parser = argparse.ArgumentParser(description="cafe_users 관리자 계정 생성/승격")
    parser.add_argument('--username', default='admin', help="관리자 계정 아이디 (기본: admin)")
    parser.add_argument('--password', default=None, help="지정하지 않으면 무작위로 생성")
    args = parser.parse_args()

    password = args.password or secrets.token_urlsafe(12)

    with app.app_context():
        db.create_all()  # 테이블이 아직 없으면 app.py 와 동일하게 생성

        user = User.query.filter_by(username=args.username).first()
        if user:
            user.password = generate_password_hash(password)
            user.role = ROLE_ADMIN
            action = "승격/비밀번호 재설정"
        else:
            user = User(
                username=args.username,
                password=generate_password_hash(password),
                role=ROLE_ADMIN,
            )
            db.session.add(user)
            action = "신규 생성"

        db.session.commit()

    print(f"[완료] '{args.username}' 계정을 관리자(role=2)로 {action}했습니다.")
    print(f"  아이디: {args.username}")
    print(f"  비밀번호: {password}")
    print("이 비밀번호는 지금 이 화면에만 출력되고 저장되지 않으니, 지금 바로 복사해두세요.")


if __name__ == '__main__':
    main()
