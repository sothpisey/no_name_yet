# router/get_access_token.py
from pydantic import BaseModel
from fastapi import APIRouter, HTTPException, Depends, status
from security.authenticator import verify_password
from security.token_handler import generate_token
from db.base import fetch_hashed_password
from fastapi.security import OAuth2PasswordRequestForm

class Token(BaseModel):
    access_token: str
    token_type: str

router = APIRouter()

@router.post('/login', response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends()):
    user_hashed_password = fetch_hashed_password(form.username)
    if not user_hashed_password or not verify_password(form.password, user_hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid username or password',
            headers={'WWW-Authenticate': 'Bearer'},
        )
    access_token = generate_token(payload={'username': form.username})
    return {'access_token': access_token, 'token_type': 'bearer'}