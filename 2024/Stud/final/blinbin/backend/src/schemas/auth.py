from marshmallow import Schema, fields

class SignupSchema(Schema):
    name = fields.String(required=True, validate=lambda n: len(n) > 0, error_messages={
        "required": "Name is required.",
        "validator_failed": "Name must be at least one character long."
    })
    password = fields.String(required=True, validate=lambda p: len(p) >= 1, error_messages={
        "required": "Password is required.",
        "validator_failed": "Password must be at least 8 characters long."
    })

class LoginSchema(Schema):
    name = fields.String(required=True, error_messages={
        "required": "Name is required."
    })
    password = fields.String(required=True, error_messages={
        "required": "Password is required."
    })


signup_schema = SignupSchema()
login_schema = LoginSchema()