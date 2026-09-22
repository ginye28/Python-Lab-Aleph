"""공공데이터(부산 테마여행) 프록시 API."""
import requests
from flask import Blueprint, current_app, jsonify

public_bp = Blueprint('public', __name__, url_prefix='/api/public')


@public_bp.route('/posts', methods=['GET'])
def get_public_posts():
    params = {
        'serviceKey': current_app.config.get('PUBLIC_API_KEY'),
        'numOfRows': '100',
        'pageNo': '1',
        'resultType': 'json'
    }
    try:
        response = requests.get(current_app.config.get('PUBLIC_API_URL'), params=params)
        if response.status_code == 200:
            return response.json()
        else:
            return jsonify({"msg": "공공 API 호출 실패", "status": response.status_code}), 500
    except Exception as e:
        return jsonify({"msg": "서버 통신 에러 발생", "error": str(e)}), 500
