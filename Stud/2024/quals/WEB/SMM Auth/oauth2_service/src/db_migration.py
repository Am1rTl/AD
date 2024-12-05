from .db import engine
from .db import SessionLocal
from datetime import datetime
from .security import get_password_hash
from .models import Base, User, OAuth2Client
from .config import get_settings
import os

def init_db():
    settings = get_settings()
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)

    session = SessionLocal()

    u1 = User(
        username="smm",
        full_name="beginner scuf",
        email="user@smm.ru",
        hashed_password=get_password_hash(password="bestprofessionforever"),
        role="user",
    )
    u2 = User(
        username=settings.flag,
        full_name="main scuf",
        email="admin@smm.ru",
        hashed_password=get_password_hash(password="Mv3_IwJ1sN4-6gGIuUmg"),
        role="admin",
    )
    session.add_all([u1, u2])
    session.commit()

    oc1 = OAuth2Client(
        client_id="smm_client_id",
        client_secret="TFX-jAApay54g_Y2",
        client_id_issued_at=datetime.utcnow(),
    )
    oc1.set_client_metadata(
        {
            "client_name": "smm-manager",
            "grant_types": ["authorization_code"],
            "redirect_uris": ["*"],
            "response_types": ["code"],
            "scope": "profile",
        }
    )
    session.add_all([oc1])
    session.commit()
