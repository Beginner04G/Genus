from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import psycopg2
import os

router = APIRouter()

# 🔐 Secret key and algorithm
SECRET_KEY = "your_secret_key_here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# 🔒 Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 🔌 Connect to Postgres
conn = psycopg2.connect(
    "postgresql://<user>:<password>@<host>:<port>/<database>?sslmode=require"
)
cur = conn.cursor()

# 📦 Models
class SignupModel(BaseModel):
    username: str
    email: EmailStr
    password: str

class LoginModel(BaseModel):
    email: EmailStr
    password: str

# 🔐 Token generation
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# 🔧 Helper
def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def hash_password(password):
    return pwd_context.hash(password)

# 📝 Signup Route
@router.post("/signup")
def signup(user: SignupModel):
    try:
        hashed_pwd = hash_password(user.password)

        cur.execute("""
            INSERT INTO "users" (username, email, password)
            VALUES (%s, %s, %s)
        """, (user.username, user.email, hashed_pwd))
        conn.commit()

        return {"message": "User registered successfully!"}
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        raise HTTPException(status_code=400, detail="User already exists")
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))

# 🔑 Login Route
@router.post("/login")
def login(data: LoginModel):
    cur.execute("""SELECT id, username, password FROM "users" WHERE email = %s""", (data.email,))
    user = cur.fetchone()

    if not user or not verify_password(data.password, user[2]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(data={"sub": data.email})
    return {"access_token": access_token, "token_type": "bearer", "username": user[1], "user_id": user[0]}
