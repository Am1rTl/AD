from src.models.post import Post
from src.extensions import ma
from marshmallow import Schema, fields


class CreatePostSchema(ma.SQLAlchemySchema):
    class Meta:
        model = Post
        load_instance = True
    
    title = fields.String(required=True, validate=lambda n: 30 > len(n) > 0, error_messages={
        "required": "Title is required.",
        "validator_failed": "Title must be 30 > 'title' > 0."
    })
    text = fields.String(required=True, validate=lambda n: len(n) > 0, error_messages={
        "required": "Text is required.",
        "validator_failed": "Text must be at least one character long."
    })
    private = fields.Boolean(required=False)



class PostSchema(ma.SQLAlchemySchema):
    class Meta:
        model = Post
        load_instance = True
        include_fk = True

    id = ma.auto_field(dump_only=True)
    title = ma.auto_field()
    text = ma.auto_field()
    private = ma.auto_field()
    author = ma.Nested("UserSchema", only=("id", "name",))
    comments = fields.Nested("CommentSchema", only=("id",))
    created_at = ma.auto_field(dump_only=True)

post_schema = PostSchema()
create_post = CreatePostSchema()