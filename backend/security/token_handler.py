# security/token_handler.py
import jwt, base64, random, os
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

load_dotenv()

#HS256_SECRET_KEY = base64.b64encode(random.randbytes(64)).decode('utf-8')
HS256_SECRET_KEY = os.getenv("HS256_SECRET_KEY")
ALGORITHM = 'HS256'
JWT_TOKEN_EXPIRE_MINUTES = timedelta(minutes=60)

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
    
def get_current_user(jwt_token: str) -> str:
    try:
        payload = jwt.decode(jwt_token, HS256_SECRET_KEY, algorithms=[ALGORITHM])
        return payload['username']
    except jwt.ExpiredSignatureError:
        raise Exception("Token has expired")
    except jwt.InvalidTokenError:
        raise Exception("Invalid token")