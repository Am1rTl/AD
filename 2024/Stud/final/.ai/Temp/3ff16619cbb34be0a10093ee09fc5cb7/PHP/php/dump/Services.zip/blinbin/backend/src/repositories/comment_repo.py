from src.models.comment import Comment
from src.extensions import db


class CommentRepository:

    @staticmethod
    def get_comment_by_id(comment_id):
        return Comment.query.get(comment_id)

    @staticmethod
    def get_comments_by_post_id(post_id):
        return Comment.query.filter(
            Comment.post_id == post_id,
        ).all()

    @staticmethod
    def get_comments_by_user_id(user_id):
        return Comment.query.filter(
            Comment.user_profile_id == user_id,
        ).all()

    @staticmethod
    def create_comment_on_post(text, author_id, post_id):
        if not isinstance(author_id, int) or not isinstance(post_id, int):
            raise ValueError("Invalid author or post ID")

        new_comment = Comment(
            text=text,
            author_id=author_id,
            post_id=post_id
        )
        db.session.add(new_comment)
        db.session.commit()
        return new_comment

    @staticmethod
    def create_comment_on_user(text, author_id, user_id):
        if not isinstance(author_id, int) or not isinstance(user_id, int):
            raise ValueError("Invalid author or user ID")

        new_comment = Comment(
            text=text,
            author_id=author_id,
            user_profile_id=user_id,
        )
        db.session.add(new_comment)
        db.session.commit()
        return new_comment


    @staticmethod
    def count_comments_for_post(post_id):
        return Comment.query.filter(
            Comment.post_id == post_id,
        ).count()
        
    @staticmethod
    def count_comments_for_user(user_id):
        return Comment.query.filter(
            Comment.user_profile_id == user_id,
        ).count()
        