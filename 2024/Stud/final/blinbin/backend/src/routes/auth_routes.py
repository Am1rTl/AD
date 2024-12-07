from flask import Blueprint, request, jsonify
from flask import session
from marshmallow import  ValidationError

from src.services.auth_service import AuthService
from src.schemas.auth import signup_schema, login_schema
from src.schemas.user import UserSchema
from src.routes.response import create_response


auth_bp = Blueprint('auth', __name__)


@auth_bp.route("/auth/signup", methods=["POST"])
def signup():
    data = signup_schema.load(request.get_json())
    name = data['name']
    password = data['password']
    AuthService.signup_user(name, password)
    return create_response('Registered successfully', 201)

@auth_bp.route('/auth/login', methods=['POST'])
def login():
    data = login_schema.load(request.get_json())
    name = data['name']
    password = data['password']
    user = AuthService.authenticate_user(name, password)
    session['user_id'] = user.id
    return create_response(UserSchema().dump(user) , 200)

@auth_bp.route('/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return create_response("Logout successful", 200)