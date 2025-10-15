from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from core.config import settings
from jose import JWTError, jwt


pwt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


def hash_password(password):
    return pwt_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwt_context.verify(plain_password, hashed_password)

def create_confirmation_token(data:dict, expire_time: timedelta = timedelta(minutes=settings.CONFIRMATION_TOKEN_EXPIRE_MINUTES)):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expire_time
    to_encode.update({'exp': expire, 'type': 'confirmation'})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

def verify_confirmation_token(token: str):
    payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=settings.JWT_ALGORITHM)
    if payload.get('type') != 'confirmation':
        raise JWTError('Not an access token')
    
    return payload
    
def create_access_token(data: dict, expire_time: timedelta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expire_time
    to_encode.update({'exp': expire, 'type': 'access'})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

def verify_access_token(token: str):
    payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=settings.JWT_ALGORITHM)
    if payload.get('type') != 'access':
        raise JWTError('Not an access token')
    
    return payload

def create_refresh_token(data: dict, expire_time: timedelta = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expire_time
    to_encode.update({'exp': expire, 'type': 'refresh'})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

def verify_refresh_token(token: str):
    payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=settings.JWT_ALGORITHM)
    if payload.get('type') != 'refresh':
        raise JWTError('Not an access token')
    
    return payload