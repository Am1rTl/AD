from src.extensions import db
from sqlalchemy.orm import relationship
from src.models.timestampmixin import TimestampMixin

class Post(TimestampMixin,db.Model):
    __tablename__ = "posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(30), nullable=False)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer,
      db.ForeignKey("users.id"),
      nullable=False)
    private = db.Column(db.Boolean, default=False)


    author = relationship("User", back_populates="posts")
    comments = relationship('Comment', back_populates='post', cascade='all, delete-orphan')
    referenced_in = relationship('Reference', back_populates='post')

