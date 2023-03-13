from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.security import OAuth2PasswordRequestForm
from datetime import datetime, timedelta
import jwt
from jwt.exceptions import PyJWTError
from core.database import SessionLocal, engine
from models.models import User, TokenData
from models.verify_password import hash_password
from .dependencies import get_current_user
from .jwt_utils import verify_password

ACCESS_TOKEN_EXPIRE_MINUTES = 30
SECRET_KEY = "your-secret-key-goes-here"

router = APIRouter()


@router.post("/login/access-token")
def login_access_token(response: Response, form_data: OAuth2PasswordRequestForm = Depends()):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == form_data.username).first()
        if not user:
            raise HTTPException(status_code=400, detail="Incorrect username or password")
        if not verify_password(form_data.password, user.hashed_password):
            raise HTTPException(status_code=400, detail="Incorrect username or password")
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username, "role": user.role.name},
            expires_delta=access_token_expires
        )
        response.set_cookie(
            key="access_token",
            value=f"Bearer {access_token}",
            expires=ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )
        return {"access_token": access_token, "token_type": "bearer"}
    except PyJWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
    finally:
        db.close()


def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")
    return encoded_jwt.decode("utf-8")
