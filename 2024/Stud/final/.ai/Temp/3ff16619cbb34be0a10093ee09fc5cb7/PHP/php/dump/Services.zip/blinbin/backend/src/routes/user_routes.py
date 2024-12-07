from flask import Blueprint, request, jsonify, session

from src.middleware.auth import login_required
from src.services.user_service import UserService
from src.services.comments_service import CommentService
from src.services.references_service import ReferenceService
from src.routes.response import create_response


from src.schemas.user import UserSchema
from src.schemas.reference import ReferenceSchema
from src.schemas.comment import comment_schema

user_bp = Blueprint('user', __name__)


@user_bp.route('/users', methods=['GET'])
def get_all_users():
    users = UserService.get_all_users()
    
    return create_response(UserSchema().dump(users, many=True), 200)

@user_bp.route('/users/<int:user_id>', methods=['GET'])
def get_user(user_id):
    sess_user_id = session.get("user_id")
    user, cleanup = UserService.get_user_by_id_with_auth(user_id, sess_user_id)
    # cleanup private posts if needed
    if cleanup:
        data = UserSchema().dump(user)
        data["posts"] = [ post for post in data["posts"] if not post["private"]]
        return create_response( data , 200)
    return create_response(UserSchema().dump(user), 200)

@user_bp.route('/users/me', methods=['GET'])
@login_required
def get_user_profile():
    user_id = session.get("user_id")
    user = UserService.get_user_by_id(user_id)
    return create_response(UserSchema().dump(user), 200)


@user_bp.route('/users/<int:user_id>/comments', methods=['GET'])
def get_comments_on_user(user_id):
    comments = CommentService.get_comments_by_user(user_id)
    return create_response(comment_schema.dump(comments, many=True), 200)

@user_bp.route('/users/<int:user_id>/comments', methods=['POST'])
@login_required
def create_comment(user_id):
    author_id = session.get("user_id")
    new_comment = comment_schema.load(request.get_json())
    text = new_comment.text
    comment = CommentService.create_comment_on_user(text, author_id, user_id)
    return create_response(comment_schema.dump(comment), 200)

@user_bp.route('/users/<int:user_id>/references', methods=['GET'])
def get_references_for_target_user(user_id):
    refs = ReferenceService.get_references_of_target_user(user_id)
    return create_response(ReferenceSchema().dump(refs, many=True), 200)

@user_bp.route('/users/<int:target_user_id>/references/<int:post_id>', methods=['POST'])
@login_required
def reference_post_to_user(target_user_id, post_id):
    author_id = session.get("user_id")
    reference = ReferenceService.create_reference_on_post_to_user(author_id, target_user_id, post_id)
    return create_response(ReferenceSchema().dump(reference), 200)


