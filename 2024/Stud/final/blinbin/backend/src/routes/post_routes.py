from flask import Blueprint, jsonify, request, session

from src.middleware.auth import login_required
from src.services.post_service import PostService
from src.services.comments_service import CommentService
from src.routes.response import create_response

from src.schemas.post import PostSchema, CreatePostSchema
from src.schemas.comment import comment_schema


post_bp = Blueprint("post", __name__)


@post_bp.route("/posts/<int:post_id>", methods=["GET"])
def get_post_by_id(post_id):
    user_id = session.get("user_id", None)
    post = PostService.get_post_by_id(post_id, user_id)
    post_schema = PostSchema()
    return create_response(post_schema.dump(post), 200)


@post_bp.route("/posts/", methods=["GET"])
def get_all_posts():
    posts = PostService.all_public_posts()
    post_schema = PostSchema(exclude=("text",))
    return create_response(post_schema.dump(posts, many=True), 200)


@post_bp.route("/posts/mine", methods=["GET"])
@login_required
def get_all_posts_of_user():
    user_id = session["user_id"]
    posts = PostService.get_all_mine_posts(user_id)
    post_schema = PostSchema()
    return create_response(post_schema.dump(posts, many=True), 200)


@post_bp.route("/posts/", methods=["POST"])
@login_required
def create_new_post():
    create_post = CreatePostSchema()
    post = create_post.load(request.get_json())
    user_id = session.get("user_id")
    post = PostService.create_post(post.title, post.text, post.private, user_id)
    post_schema = PostSchema()
    return create_response(post_schema.dump(post), 201)


@post_bp.route("/posts/<int:post_id>", methods=["POST"])
@login_required
def update_post_visibility(post_id):
    """
    update post access status
    """
    data = request.get_json()
    private = bool(data["private"])
    user_id = session.get("user_id")
    PostService.change_visibility_of_post(post_id, private, user_id)
    return create_response("done", 200)


@post_bp.route("/posts/accessible/<string:post_title>", methods=["POST"])
@login_required
def check_post_visibility(post_title):
    """
    check if post accessible to this user
    """
    data = request.get_json()
    private = data.get("private", None)
    user_id = session.get("user_id")
    status = PostService.ask_if_status_of_post_equals(post_title, private, user_id)
    return create_response({"status": status}, 200)


@post_bp.route("/posts/<int:post_id>/comments", methods=["GET"])
def get_comments_of_post(post_id):
    user_id = session.get("user_id")
    comments = CommentService.get_comments_by_post_id(post_id, user_id)
    return create_response(comment_schema.dump(comments, many=True), 200)


@post_bp.route("/posts/<int:post_id>/comments", methods=["POST"])
@login_required
def create_comment(post_id):
    user_id = session.get("user_id")
    # TODO: perhaps IDOR or Mass Assignment?
    new_comment = comment_schema.load(request.get_json())
    text = new_comment.text
    comment = CommentService.create_comment_on_post(text, user_id, post_id)
    return create_response(comment_schema.dump(comment), 201)
