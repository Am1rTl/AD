from src.repositories.comment_repo import CommentRepository
from src.repositories.post_repo import PostRepository
from src.repositories.user_repo import UserRepository

from src.services.post_service import PostService
from src.services.exception import ApiException

from src.models.post import Post
from src.models.comment import Comment


class CommentService:

    @staticmethod
    def get_comments_by_user(user_id):
        return CommentRepository.get_comments_by_user_id(user_id)

    @staticmethod
    def get_comments_by_post_id(post_id, user_id):

        post: Post = PostRepository.get_post_by_id(post_id)
        if post is None:
            raise ApiException("Post not found", 404)

        if not PostService.is_allowed_to_access_post(post.id, user_id):
            raise ApiException("Authentication required", 403)

        return CommentRepository.get_comments_by_post_id(post.id)

    @staticmethod
    def create_comment_on_post(text: str, author_id: int, post_id: int) -> Comment:
        post = PostRepository.get_post_by_id(post_id)
        if post is None:
            raise ApiException("Post not found")

        author = UserRepository.get_user_by_id(author_id)
        if author is None:
            raise ApiException("User not found")

        # Check if the user is allowed to access the post
        if not PostService.is_allowed_to_access_post(post.id, author.id):
            raise ApiException("Authentication required", 403)

        return CommentRepository.create_comment_on_post(text, author.id, post.id)

    @staticmethod
    def create_comment_on_user(text, author_id, user_id):

        author = UserRepository.get_user_by_id(author_id)
        if author is None:
            raise ApiException("Authentication required", 403)

        user = UserRepository.get_user_by_id(user_id)
        if user is None:
            raise ApiException("User not found", 404)

        return CommentRepository.create_comment_on_user(text, author.id, user.id)
