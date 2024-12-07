import os
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = str(Path(__file__).parent.parent)
load_dotenv()

class Config(object):
    LOG_LEVEL = os.environ.get("LOG_LEVEL", 'INFO')
    APP_DIR = os.path.abspath(os.path.dirname(__file__))
    PROJECT_ROOT = os.path.abspath(os.path.join(APP_DIR, os.pardir))

    SECRET_KEY = os.environ.get("SECRET_KEY", "secret_key")
    SESSION_TYPE = "filesystem"

    CORS_ORIGIN_WHITELIST = [
        '*',
    ]

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = os.environ.get("SQLALCHEMY_DATABASE_URI", "sqlite:///app.db")
    API_PREFIX = os.environ.get("SERVICE_PREFIX", '/api')

    def __setitem__(self, key, item):
        self.__dict__[key] = item

    def __getitem__(self, key):
        return self.__dict__[key]