from src.models.post import Post
from src.extensions import db
from datetime import datetime, timedelta


class PostRepository:

    @staticmethod
    def get_post_by_id(post_id):
        return Post.query.get(post_id)

    @staticmethod
    def get_all_posts():
        thirty_minutes_ago = datetime.utcnow() - timedelta(minutes=30)
        return Post.query.filter(Post.created_at >= thirty_minutes_ago).all()

    @staticmethod
    def get_all_public_posts():
        return Post.query.filter(Post.private == False).all()

    @staticmethod
    def create_post(text, title, private, author_id):
        new_post = Post(title=title, text=text, private=private, author_id=author_id)
        db.session.add(new_post)
        db.session.commit()
        return new_post

    @staticmethod
    def get_all_posts_by_author(author_id):
        return Post.query.filter(Post.author_id == author_id).all()

    @staticmethod
    def update_private_status(post_id, private):
        post: Post = Post.query.get(post_id)
        post.private = private
        db.session.commit()
        return post

    @staticmethod
    def get_post_by_strict_title(post_title):
        return Post.query.filter(Post.title == post_title).first()