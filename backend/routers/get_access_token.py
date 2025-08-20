# router/get_access_token.py
from pydantic import BaseModel
from fastapi import APIRouter, HTTPException
from security.authenticator import verify_password
from security.token_handler import generate_token
from db.base import fetch_hashed_password

class Token(BaseModel):
    access_token: str
    token_type: str

class VerificationForm(BaseModel):
    user_name: str
    password: str

router = APIRouter()
    
@router.post('/get_access_token', response_model=Token)
def get_access_token(form: VerificationForm):
    user_hashed_password = fetch_hashed_password(form.user_name)
    if not user_hashed_password or not verify_password(form.password, user_hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    payload = {'username': form.user_name}
    token = generate_token(payload)
    return Token(access_token=token, token_type='bearer')