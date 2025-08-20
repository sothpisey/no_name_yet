# routers/get_user_info.py
from fastapi import APIRouter, Depends
from db.base import fetch_user_info
from security.token_handler import get_current_user

router = APIRouter()

@router.get("/user_info")
def get_user_info(username: str = Depends(get_current_user)):
    user_info = fetch_user_info(username, is_username=True)
    if user_info:
        return user_info
    return {"error": "User not found"}