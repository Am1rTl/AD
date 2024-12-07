from flask import Flask
from flask_cors import CORS
import logging


from src.routes import register_routes
from src.extensions import db, migrate, ma
from src.error_handler import setup_error_handler
from src.logging import setup_logging

def create_app(
    config,
):
    app = Flask(__name__.split('.')[0])
    # app = setup_logging(app)
    app.config.from_object(config)

    app.url_map.strict_slashes = False
    
    # Initialize extensions
    db.init_app(app)
    ma.init_app(app)
    migrate.init_app(app, db)
    CORS(app, supports_credentials=True)

    app = setup_error_handler(app)
    app = setup_logging(app)
    # Register routes
    register_routes(app, app.config.get("API_PREFIX"))

    return app