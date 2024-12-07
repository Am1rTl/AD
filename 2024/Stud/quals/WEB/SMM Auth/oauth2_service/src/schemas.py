from pydantic import BaseModel


class AdminToLoginSystemModel(BaseModel):
    redirect_uri: str
