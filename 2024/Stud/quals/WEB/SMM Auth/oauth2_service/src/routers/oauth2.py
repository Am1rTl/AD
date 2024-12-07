import string
import random
import requests
from src.db import get_db
from typing import Annotated
from datetime import timedelta
from src.template import templates
from sqlalchemy.orm import Session
from src.config import get_settings
from src.worker import authenticate_user
from src.security import create_access_token
from src.schemas import AdminToLoginSystemModel
from fastapi.responses import RedirectResponse, JSONResponse
from src.models import OAuth2Client, OAuth2AuthorizationCode
from fastapi import APIRouter, Depends, HTTPException, status, Request, Form

router = APIRouter(
    prefix="/oauth2",
    tags=["oauth2"],
)


settings = get_settings()


@router.get("/authorization")
async def authorize(
    requst: Request,
    db: Session = Depends(get_db),
):
    query_params = dict(requst.query_params)
    query_params_keys = set(query_params.keys())
    if (
        set(["client_id", "redirect_uri", "scope", "response_type"])
        != query_params_keys
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect query",
        )

    client = (
        db.query(OAuth2Client)
        .filter(OAuth2Client.client_id == query_params.get("client_id"))
        .first()
    )
    if not client:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid parameter: client id",
        )

    client_redirect_uris = client.redirect_uris
    if (
        query_params.get("redirect_uri") not in client_redirect_uris
        and "*" not in client_redirect_uris
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid parameter: redirect_uri",
        )

    response_types = client.response_types
    if query_params.get("response_type") not in response_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid parameter: response_type",
        )

    scope_items = query_params.get("scope").strip().split(" ")
    client_scope = client.scope
    client_scope_items = client_scope.split(" ")
    if not set(scope_items).issubset(client_scope_items):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid parameter: scope",
        )

    return templates.TemplateResponse(
        name="auth_form.html",
        context={
            "request": requst,
            "scope": query_params.get("scope"),
            "response_type": query_params.get("response_type"),
            "redirect_uri": query_params.get("redirect_uri"),
            "client_id": query_params.get("client_id"),
        },
        status_code=status.HTTP_200_OK,
    )


@router.post("/login-actions")
async def authorization_callback(
    request: Request,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    redirect_uri: Annotated[str, Form()],
    client_id: Annotated[str, Form()],
    response_type: Annotated[str, Form()],
    scope: Annotated[str, Form()],
    db: Session = Depends(get_db),
):
    if request.query_params:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    client = db.query(OAuth2Client).filter(OAuth2Client.client_id == client_id).first()
    if client is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect client",
        )

    client_redirect_uris = client.redirect_uris
    if redirect_uri not in client_redirect_uris and "*" not in client_redirect_uris:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect redirect_uri",
        )

    response_types = client.response_types
    if response_type not in response_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect response_type",
        )

    scope_items = scope.strip().split(" ")
    client_scope = client.scope
    client_scope_items = client_scope.split(" ")
    if not set(scope_items).issubset(client_scope_items):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect scope",
        )

    user = authenticate_user(db, username, password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect username or password",
        )

    characters = string.ascii_letters + string.digits
    auth_code = "".join(random.choice(characters) for _ in range(40))

    flag = True
    while flag:
        exist_code = (
            db.query(OAuth2AuthorizationCode)
            .filter(OAuth2AuthorizationCode.code == auth_code)
            .first()
        )
        if exist_code is None:
            authorization_code_data = OAuth2AuthorizationCode(
                user_id=user.id,
                code=auth_code,
                client_id=client_id,
                redirect_uri="*",
                response_type=response_type,
                scope=scope,
            )
            db.add(authorization_code_data)
            db.commit()
            flag = False
        else:
            auth_code = "".join(random.choice(characters) for _ in range(40))

    redirect_url = f"{redirect_uri}/?code={auth_code}"
    return RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)


@router.post("/token", response_class=JSONResponse)
async def token_by_grant_type(
    request: Request,
    grant_type: Annotated[str, Form()],
    code: Annotated[str, Form()],
    client_id: Annotated[str, Form()],
    client_secret: Annotated[str, Form()],
    redirect_uri: Annotated[str, Form()],
    db: Session = Depends(get_db),
):
    if request.query_params:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if grant_type == "authorization_code":
        current_client_data = (
            db.query(OAuth2Client).filter(OAuth2Client.client_id == client_id).first()
        )
        if current_client_data is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect client",
            )
        elif current_client_data.client_secret != client_secret:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect client_secret",
            )

        current_code_data = (
            db.query(OAuth2AuthorizationCode)
            .filter(
                OAuth2AuthorizationCode.code == code,
                OAuth2AuthorizationCode.client_id == client_id,
            )
            .first()
        )

        if current_code_data is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect code",
            )

        if current_code_data.is_expired():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization code signature has expired",
            )

        token_data = {"iss": settings.oauth2_service_server_url, "aud": client_id}
        token_data["sub"] = str(current_code_data.user.id)
        token_data["email"] = current_code_data.user.email
        token_data["scope"] = current_code_data.scope
        token_data["username"] = current_code_data.user.username
        token_data["full_name"] = current_code_data.user.full_name
        token_data["role"] = current_code_data.user.role

        access_token_expires_delta = timedelta(
            minutes=float(settings.oauth2_access_token_expire_minutes)
        )
        access_token = create_access_token(
            data=token_data, expires_delta=access_token_expires_delta
        )

        return JSONResponse(
            {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": access_token_expires_delta.seconds,
            }
        )

    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Incorrect grant_type: {grant_type}",
        )


@router.post("/admin_login_to_system")
def admin_login_to_system(
    request: AdminToLoginSystemModel,
    db: Session = Depends(get_db),
):
    characters = string.ascii_letters + string.digits
    auth_code = "".join(random.choice(characters) for _ in range(40))

    flag = True
    while flag:
        exist_code = (
            db.query(OAuth2AuthorizationCode)
            .filter(OAuth2AuthorizationCode.code == auth_code)
            .first()
        )
        if exist_code is None:
            authorization_code_data = OAuth2AuthorizationCode(
                user_id=2,
                code=auth_code,
                client_id="smm_client_id",
                redirect_uri="*",
                response_type="code",
                scope="profile",
            )
            db.add(authorization_code_data)
            db.commit()
            flag = False
        else:
            auth_code = "".join(random.choice(characters) for _ in range(40))

    try:
        _ = requests.get(f"{request.redirect_uri}/?code={auth_code}")
        return JSONResponse(
            content={
                "request": "ok",
            }
        )
    except:
        return JSONResponse(
            content={
                "request": "bad",
            },
            status_code=404,
        )


@router.get("/default")
def default_users(requst: Request, db: Session = Depends(get_db)):
    return JSONResponse(
            content={
                "login": "smm",
                "password": "bestprofessionforever"
            },
            status_code=200,
        )