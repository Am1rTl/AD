from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    ip: str
    smm_service_port: str
    oauth2_service_port: str

    db_host_uri: str

    oauth2_service_server_url: str
    oauth2_service_token_endpoint: str
    oauth2_service_authorization_endpoint: str

    client_id: str
    client_secret_key: str

    smm_service_redirect_uri: str
    grant_type: str

    algorithm: str

    oauth2_service_admin_login_vulnerability: str

    #class Config:
    #   env_file = "./.env"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
