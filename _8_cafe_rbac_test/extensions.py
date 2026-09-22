"""확장(Extension) 객체를 한 곳에서 만든다.

app 과 분리해 두면 models·controllers 어디서든 import 해도
순환 참조(circular import)가 생기지 않는다.
"""
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
jwt = JWTManager()
