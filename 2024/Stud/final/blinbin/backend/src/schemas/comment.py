from src.models.comment import Comment
from src.extensions import ma
from marshmallow import fields


class CommentSchema(ma.SQLAlchemySchema):
    class Meta:
        model = Comment
        load_instance = True
        
    id = ma.Integer(dump_only=True)
    text = fields.String(required=True, validate=lambda n: len(n) > 0, error_messages={
        "required": "Text is required.",
        "validator_failed": "Text must be at least one character long."
    })
    author = fields.Nested("UserSchema", only=["id", "name"])
    


comment_schema = CommentSchema()