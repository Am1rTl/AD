from src.config import get_settings
from fastapi.responses import JSONResponse
from fastapi import APIRouter, Request, HTTPException, status


settings = get_settings()


well_known_router = APIRouter(
    prefix="/.well-known",
    tags=["well-known"],
)


@well_known_router.get(
    "/openid-configuration",
    response_class=JSONResponse,
)
async def openid_config(request: Request):
    if request.query_params:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    openid_cfg = {
        "scope_supported": {
            "profile": "profile scope",
        },
        "issuer": settings.oauth2_service_server_url,
        "authorization_endpoint": settings.oauth2_service_authorization_endpoint,
        "token_endpoint": settings.oauth2_service_token_endpoint,
        "grant_types_supported": [
            "authorization_code",
        ],
        "jwks_uri": settings.oauth2_service_server_url,
        "default_users_endpoint": settings.oauth2_default_users_endpoint,
    }

    return JSONResponse(content=openid_cfg)
