from src.extensions import db
from sqlalchemy.orm import relationship
from src.models.timestampmixin import TimestampMixin


class Reference(TimestampMixin, db.Model):
    __tablename__ = "references"

    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    author = relationship("User", backref="references_authored", foreign_keys=[author_id])


    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)
    user_profile_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    post = relationship('Post', back_populates='referenced_in', foreign_keys=[post_id])
    # user_profile = relationship('User', backref='profile_references', foreign_keys=[user_profile_id])