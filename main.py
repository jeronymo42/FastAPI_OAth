from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWSError, jwt
from passlib.context import CryptContext

SECRET_KEY = "3c69a3aa553fa445d1552408d84b1370dc9db3db887ece6be694c181aad7aace"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

fake_user_db = {
    "Vladimir": {
        "username": "jeronymo",
        "full_name": "Vladimir",
        "email":"-",
        "hashed_password":"",
        "disabled": False
    }
}

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str or None = None

class User(BaseModel):
    username: str
    full_name: str or None = None
    email: str or None = None
    disabled: bool or None = None

class UserInDB(User):
    hashed_password: str

pwd_context = CryptContext(schemes=["bcrypt"])
oath_2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

