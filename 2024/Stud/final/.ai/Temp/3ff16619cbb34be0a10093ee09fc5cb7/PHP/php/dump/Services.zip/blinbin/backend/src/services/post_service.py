from src.repositories.post_repo import PostRepository
from src.repositories.user_repo import UserRepository
from src.services.exception import ApiException

from src.models.post import Post
from src.models.user import User

from string import printable
import logging


class PostService:

    @staticmethod
    def all_public_posts():
        return PostRepository.get_all_public_posts()

    @staticmethod
    def is_allowed_to_access_post(post_id, user_id):
        post = PostRepository.get_post_by_id(post_id)

        if not post or not post.private:
            return True

        if not user_id:
            raise ApiException("Authentication required (user not found)", 403)

        requesting_user = UserRepository.get_user_by_id(user_id)

        if requesting_user.id != post.author_id:
            raise ApiException("Authentication required (you are not owner)", 403)

        return True

    @staticmethod
    def get_post_by_id(post_id, user_id):

        post: Post = PostRepository.get_post_by_id(post_id)
        if post is None:
            raise ApiException("Post not found", 404)

        return post if PostService.is_allowed_to_access_post(post.id, user_id) else None

    # TODO: text/title
    @staticmethod
    def create_post(title, text, private, author_id):

        if not text or not text.strip():
            raise ApiException("Text cannot be empty", 400)

        author = UserRepository.get_user_by_id(author_id)
        if author is None:
            raise ApiException("User not found", 404)


        author = UserRepository.get_user_by_id(author_id)
        if author is None:
            raise ApiException("User not found", 404)

        return PostRepository.create_post(text, title, private, author_id)

    @staticmethod
    def get_all_mine_posts(user_id):
        return PostRepository.get_all_posts_by_author(user_id)

    @staticmethod
    def change_visibility_of_post(post_id, private, user_id):
        if user_id is None:
            raise ApiException("Authentication required (user not found)", 403)

        author: User = UserRepository.get_user_by_id(user_id)
        if author is None:
            raise ApiException("Authentication required (author not found)", 403)

        post: Post = PostRepository.get_post_by_id(post_id)

        if post.author_id != author.id:
            raise ApiException("Can't access this post (you are not owner)", 403)

        post = PostRepository.update_private_status(post_id, private)
        return post

    @staticmethod
    def ask_if_status_of_post_equals(post_title, private, user_id):
        '''
        карты карно люблю....
        private - ожидаю паблик ?
        False - да
        True - нет
        '''
        if user_id is None:
            raise ApiException("Authentication required (user not found)", 403)
        
        if not isinstance(private, bool):
            raise ApiException("Invalid status type: must be bool", 400)


        checker: User = UserRepository.get_user_by_id(user_id)
        if checker is None:
            raise ApiException("Authentication required (user not found)", 403)

        post: Post = PostRepository.get_post_by_strict_title(post_title)
        if post is None:
            raise ApiException("Post not found", 404)
        
        a = post.author_id == checker.id
        b = post.private
        c = private

        '''
            (!c) +((!a)*b*c)
            совпало ли ожидание с реальностью?

        '''
        return (not c) or ((not a) and b and c)