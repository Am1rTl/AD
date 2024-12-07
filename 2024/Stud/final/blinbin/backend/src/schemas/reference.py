from src.models.reference import Reference
from src.extensions import ma
from marshmallow import fields

class ReferenceSchema(ma.SQLAlchemySchema):
    class Meta:
        model = Reference
        load_instance = True
        
    
    id = ma.Integer(dump_only=True)
    author = fields.Nested("UserSchema", only=["id", "name"])
    post_id = ma.Integer(dump_only=True)
    post = fields.Nested("PostSchema", only=["id", "title"])
    user_profile_id = ma.Integer(dump_only=True)    
