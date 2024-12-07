from .templates import templates
from fastapi import FastAPI, Request
from .database_migration import init_db
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from .services.client.client_router import client_router
from .services.proxy.oauth_proxy_router import proxy_router
from starlette.exceptions import HTTPException as StarletteHTTPException


def init_router(_app: FastAPI) -> None:
    _app.include_router(client_router)
    _app.include_router(proxy_router)


def init_database() -> None:
    init_db()


def init_middleware(_app: FastAPI) -> None:
    _app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


def init_app() -> FastAPI:
    _app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    init_middleware(_app)
    init_router(_app)
    init_database()
    return _app


app = init_app()
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    return templates.TemplateResponse(
        name="error.html",
        context={
            "request": request,
            "status_code": exc.status_code,
            "detail": exc.detail,
        },
        status_code=exc.status_code,
    )
