# security/token_handler.py
import jwt, os
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

load_dotenv()

HS256_SECRET_KEY = os.getenv("HS256_SECRET_KEY")
ALGORITHM = 'HS256'
JWT_TOKEN_EXPIRE_MINUTES = timedelta(minutes=int(os.getenv('TOKEN_EXPIRE_MINUTES')))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def generate_token(payload: dict, hs256_secret_key: str = HS256_SECRET_KEY, expires_delta: timedelta | None = None) -> str:
    payload = payload.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=60)
    payload = {'username': payload['username'], 'exp': int(expire.timestamp())}
    jwt_token = jwt.encode(payload, hs256_secret_key, algorithm=ALGORITHM)
    return jwt_token


def verify_token(jwt_token: str, hs256_secret_key: str = HS256_SECRET_KEY) -> bool:
    try:
        jwt.decode(jwt_token, hs256_secret_key, algorithms=[ALGORITHM])
        return True
    except:
        return False
    
def get_current_user(jwt_token: str = Depends(oauth2_scheme)) -> str:
    try:
        payload = jwt.decode(jwt_token, HS256_SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('username')
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='Invalid token: missing username',
                headers={'WWW-Authenticate': 'Bearer'},
            )
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Token expired',
            headers={'WWW-Authenticate': 'Bearer'},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )