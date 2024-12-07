from src.models.user import User
from src.models.post import Post
from src.extensions import ma
from marshmallow import fields

class UserSchema(ma.SQLAlchemySchema):
    class Meta:
        model = User
        load_instance = True  # Deserialization to a model instance

    id = ma.auto_field()
    name = ma.auto_field()
    posts_count = fields.Function(lambda user: len(user.posts))
    posts = fields.List(fields.Nested("PostSchema", only=("id","title", "comments","created_at", "private")))

    # Exclude the `password` field from serialization
    password = ma.auto_field(load_only=True)