from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    ip: str
    oauth2_service_port: str

    db_host_uri: str

    oauth2_service_server_url: str
    oauth2_service_token_endpoint: str
    oauth2_service_authorization_endpoint: str
    oauth2_default_users_endpoint: str

    algorithm: str
    oauth2_access_token_expire_minutes: str
    flag: str

    #class Config:
    #    env_file = "./.env"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
