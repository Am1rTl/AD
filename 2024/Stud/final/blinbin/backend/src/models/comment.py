from src.extensions import db
from sqlalchemy.orm import relationship
from src.models.timestampmixin import TimestampMixin


class Comment(TimestampMixin, db.Model):
    __tablename__ = "comments"

    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    author = relationship("User", backref="comments_authored", foreign_keys=[author_id])


    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=True)
    user_profile_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    post = relationship('Post', back_populates='comments', foreign_keys=[post_id])
    user_profile = relationship('User', backref='profile_comments', foreign_keys=[user_profile_id])