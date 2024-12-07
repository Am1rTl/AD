import requests
from jose import jwt
from src.config import get_settings
from fastapi.security import OAuth2
from typing import Any, Dict, Optional, cast
from src.services.oauth2_integration.oauth2_models import User
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.security.utils import get_authorization_scheme_param
from fastapi import Security, HTTPException, status, Depends, Request


settings = get_settings()


class OAuth2AuthorizationCodeBearerByCookie(OAuth2):
    def __init__(
        self,
        authorizationUrl: str,
        tokenUrl: str,
        refreshUrl: Optional[str] = None,
        scheme_name: Optional[str] = None,
        scopes: Optional[Dict[str, str]] = None,
        description: Optional[str] = None,
        auto_error: bool = True,
    ):
        if not scopes:
            scopes = {}
        flows = OAuthFlowsModel(
            authorizationCode=cast(
                Any,
                {
                    "authorizationUrl": authorizationUrl,
                    "tokenUrl": tokenUrl,
                    "refreshUrl": refreshUrl,
                    "scopes": scopes,
                },
            )
        )
        super().__init__(
            flows=flows,
            scheme_name=scheme_name,
            description=description,
            auto_error=auto_error,
        )

    async def __call__(self, request: Request) -> Optional[str]:
        authorization = request.cookies.get("Authorization")
        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            else:
                return None
        return param


oauth_scheme = OAuth2AuthorizationCodeBearerByCookie(
    authorizationUrl=settings.oauth2_service_authorization_endpoint,
    tokenUrl=settings.oauth2_service_token_endpoint,
    auto_error=False,
)


def fetch_jwks() -> dict[str, str | int]:
    jwks_response = requests.get(url=settings.oauth2_service_server_url)
    return jwks_response.json()


async def get_idp_public_key():
    try:
        return (
            "-----BEGIN PUBLIC KEY-----\n"
            f"{fetch_jwks()['public_key']}"
            "\n-----END PUBLIC KEY-----"
        )
    except:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Public key not found",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_payload_private(token: str | None = Security(oauth_scheme)) -> dict:
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        key = await get_idp_public_key()
        token_info = jwt.decode(
            token, key, algorithms=[settings.algorithm], options={"verify_aud": False}
        )
        return token_info
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_user_info_private(payload: dict = Depends(get_payload_private)) -> User:
    return User(username=payload.get("username"))


async def get_payload_public(
    request: Request, token: str | None = Security(oauth_scheme)
) -> dict:
    if token is None:
        if not request.cookies:
            return None
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Suspicious activity. Do not try to substitute cookies",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        key = await get_idp_public_key()
        token_info = jwt.decode(
            token, key, algorithms=["RS256"], options={"verify_aud": False}
        )
        return token_info
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Suspicious activity. Do not try to substitute cookies",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_user_info_public(
    payload: dict | None = Depends(get_payload_public),
) -> User:
    if payload is None:
        return None
    return User(username=payload.get("username"))
