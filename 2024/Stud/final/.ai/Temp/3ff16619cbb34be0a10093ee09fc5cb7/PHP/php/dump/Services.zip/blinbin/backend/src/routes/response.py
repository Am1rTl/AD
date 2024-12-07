from flask import jsonify, request, session
from flask import jsonify, request
from werkzeug.exceptions import ImATeapot

def create_response(data=None, status_code=200):
    if isinstance(data, str):
        return jsonify({'message': data, 'status_code': status_code, "data": None}), status_code
    elif isinstance(data, dict) or isinstance(data, list):
        return jsonify({'message': 'ok', 'status_code': status_code, 'data': data}), status_code
    else:
        raise ImATeapot(" with tea")
