from .user_routes import user_bp
from .meta_routes import meta_bp
from .post_routes import post_bp
from .auth_routes import auth_bp


def register_routes(app, prefix: str):
    app.register_blueprint(user_bp, url_prefix=prefix)
    app.register_blueprint(meta_bp, url_prefix=prefix)
    app.register_blueprint(post_bp, url_prefix=prefix)
    app.register_blueprint(auth_bp, url_prefix=prefix)
