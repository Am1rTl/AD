from src.extensions import db
from sqlalchemy.sql import func
from sqlalchemy.ext.declarative import declared_attr

class TimestampMixin(object):
    created_at = db.Column(db.DateTime(timezone=True), default=func.now())
    updated_at = db.Column(db.DateTime(timezone=True), default=func.now(), onupdate=func.now())

    @declared_attr
    def __tablename__(cls):
        return cls.__name__.lower()
