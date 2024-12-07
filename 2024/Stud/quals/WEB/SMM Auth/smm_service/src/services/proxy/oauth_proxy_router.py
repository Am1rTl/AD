import requests
from src.config import get_settings
from src.worker import get_token_request
from fastapi.responses import RedirectResponse
from fastapi import APIRouter, HTTPException, Request, status


settings = get_settings()


proxy_router = APIRouter(
    prefix="/proxy",
    tags=["proxy"],
)


@proxy_router.get("/callback")
async def callback(request: Request):
    callback_data = dict(request.query_params)
    if set(["code"]) != set(callback_data.keys()):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid query",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        code = request.query_params.get("code")
        data, headers = get_token_request(code=code)
        response = requests.post(
            settings.oauth2_service_token_endpoint, data=data, headers=headers
        )
        token_data = response.json()

        response = RedirectResponse(
            url="/", status_code=status.HTTP_307_TEMPORARY_REDIRECT
        )
        response.set_cookie(
            key="Authorization",
            value=f"{token_data.get('token_type')} {token_data.get('access_token')}",
            expires=token_data.get("expires_in"),
        )
        return response
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Bearer"},
        )
