from flask import Blueprint, request, jsonify
from src.routes.response import create_response

meta_bp = Blueprint('meta', __name__)


@meta_bp.route('/healthcheck', methods=['GET'])
def healthcheck():
    return create_response({"app": "healthy"}, 200)