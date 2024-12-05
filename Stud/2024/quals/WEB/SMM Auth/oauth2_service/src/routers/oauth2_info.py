from src.config import get_settings
from src.security import get_public_key
from fastapi.responses import JSONResponse
from fastapi import APIRouter, HTTPException, Request, status


oauth2_router = APIRouter()
settings = get_settings()


@oauth2_router.get("/")
def get_oauth2_info(request: Request):
    if request.query_params:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    key = get_public_key()
    return JSONResponse(
        content={
            "public_key": key,
            "token_service": settings.oauth2_service_token_endpoint,
        }
    )
