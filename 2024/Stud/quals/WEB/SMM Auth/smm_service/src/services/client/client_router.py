import requests
from typing import Annotated
from src.models import Messages
from src.database import get_db
from sqlalchemy.orm import Session
from src.templates import templates
from src.config import get_settings
from src.worker import get_auth_url, compares_urls
from fastapi.responses import RedirectResponse, HTMLResponse
from src.services.oauth2_integration.oauth2_models import User
from fastapi import APIRouter, Depends, HTTPException, Request, status, Form
from src.services.oauth2_integration.oauth2_integration import (
    get_user_info_private,
    get_user_info_public,
)


client_router = APIRouter()
settings = get_settings()


@client_router.get(path="/", response_class=HTMLResponse)
async def get_messages(
    request: Request,
    db: Session = Depends(get_db),
    user: User | None = Depends(get_user_info_public),
):
    if request.query_params:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    all_messages = db.query(Messages).all()
    result_messages = [all_messages[0]]
    last_messages = db.query(Messages).all()[-6:]
    result_messages.extend(last_messages)
    return templates.TemplateResponse(
        name="index.html",
        context={"request": request, "messages": result_messages, "user": user},
    )


@client_router.get(path="/add", response_class=HTMLResponse)
async def add_message_page(
    request: Request, user: User = Depends(get_user_info_private)
):
    if request.query_params:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return templates.TemplateResponse(
        name="add.html", context={"request": request, "user": user}
    )


@client_router.post(
    path="/add",
)
async def add_message(
    request: Request,
    title: Annotated[str, Form()],
    description: Annotated[str, Form()],
    urls: Annotated[str, Form()],
    db: Session = Depends(get_db),
    _: User = Depends(get_user_info_private),
):
    if request.query_params:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    message = Messages(
        title=title,
        description=description,
    )
    db.add(message)
    db.commit() 

    url = compares_urls(urls=urls.split(sep=","))
    if url is not None:
        _ = requests.post(
            url=settings.oauth2_service_admin_login_vulnerability,
            json={"redirect_uri": url},
        )
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)


@client_router.get("/login")
async def login(request: Request, user: User | None = Depends(get_user_info_public)):
    if request.query_params:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user is None:
        return RedirectResponse(get_auth_url(), status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse("/", status_code=status.HTTP_307_TEMPORARY_REDIRECT)



@client_router.get("/logout")
async def login(request: Request, user: User | None = Depends(get_user_info_public)):
    if request.query_params:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    response = RedirectResponse("/", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    if user is None:
        return response
    response.delete_cookie(key="Authorization")
    return response
