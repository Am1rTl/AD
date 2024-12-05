from .db_migration import init_db
from src.template import templates
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from .routers import oauth2, well_known, oauth2_info
from starlette.exceptions import HTTPException as StarletteHTTPException


def init_router(_app: FastAPI):
    _app.include_router(oauth2.router)
    _app.include_router(oauth2_info.oauth2_router)
    _app.include_router(well_known.well_known_router)


def init_database():
    init_db()


def init_middleware(_app: FastAPI):
    _app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


def init_app():
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
