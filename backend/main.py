from fastapi import FastAPI, Depends
from db.base import fetch_all
from routers import get_access_token, get_user_info
from security.token_handler import get_current_user

app = FastAPI()

app.include_router(get_access_token.router)
app.include_router(get_user_info.router)
