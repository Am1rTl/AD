from src.extensions import db
from src.models.timestampmixin import TimestampMixin
from sqlalchemy.orm import relationship

class User(TimestampMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    password = db.Column(db.String(255), nullable=False)

    posts = relationship("Post", back_populates="author")

    #comments_authored = relationship("Comment", back_populates="author", foreign_keys="Comment.author_id")

