from jose import jwt
from src.config import get_settings
from datetime import timedelta, datetime
from passlib.context import CryptContext
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


settings = get_settings()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


private_key_obj = rsa.generate_private_key(
    public_exponent=65537, key_size=2048, backend=default_backend()
)
SECRET_KEY = private_key_obj.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode("utf-8")


public_key_obj = private_key_obj.public_key()
PUBLIC_KEY = public_key_obj.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode("utf-8")


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if not expires_delta:
        expires_delta = timedelta(minutes=settings.oauth2_access_token_expire_minutes)
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=settings.algorithm)
    return encoded_jwt


def decode_access_token(token: str, audience: str = None, options: dict = {}):
    payload = jwt.decode(
        token,
        PUBLIC_KEY,
        algorithms=[settings.algorithm],
        audience=audience,
        options=options,
    )
    return payload


def get_public_key():
    return "".join(PUBLIC_KEY.splitlines()[1:-1])


def get_password_hash(password: str):
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)
