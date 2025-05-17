from fastapi import FastAPI, HTTPException, Depends, Security
from pydantic import BaseModel, EmailStr
from datetime import datetime, date, timedelta
from jose import jwt, JWTError
from passlib.context import CryptContext
import psycopg2
import  os
import psycopg2.errors
from contextlib import closing
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # or list your Flutter app URL here
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ DATABASE CONFIG
DB_URL = os.getenv("DB_URL")

# ✅ AUTH CONFIG
SECRET_KEY = os.getenv("SECRET_KEY")
print("DB_URL:", DB_URL)
print("SECRET_KEY:", SECRET_KEY)

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

security = HTTPBearer()

# ✅ Pydantic Models
class SignupModel(BaseModel):
    username: str
    email: EmailStr
    password: str


class LoginModel(BaseModel):
    email: EmailStr
    password: str


# ✅ Utility Functions
def hash_password(password: str):
    return pwd_context.hash(password)


def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)


def create_token(data: dict):
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# ✅ SIGNUP API
@app.get("/")
def read_root():
    return {"message": "FastAPI is running"}

@app.post("/signup")
def signup(user: SignupModel):
    try:
        with closing(psycopg2.connect(DB_URL)) as conn:
            with conn.cursor() as cur:
                hashed_pwd = hash_password(user.password)
                cur.execute("""
                    INSERT INTO "users" (username, email, password)
                    VALUES (%s, %s, %s)
                """, (user.username, user.email, hashed_pwd))
                conn.commit()
        return {"message": "User created successfully"}
    except psycopg2.errors.UniqueViolation:
        raise HTTPException(status_code=400, detail="User already exists")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ✅ LOGIN API
@app.post("/login")
def login(data: LoginModel):
    try:
        conn = psycopg2.connect(DB_URL)
        cur = conn.cursor()
        cur.execute('SELECT id, username, password FROM "users" WHERE email = %s', (data.email,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if not user or not verify_password(data.password, user[2]):
            raise HTTPException(status_code=401, detail="Invalid email or password")

        token = create_token({"sub": data.email})

        return {
            "access_token": token,
            "token_type": "bearer",
            "username": user[1],
            "user_id": user[0]
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ✅ METER CHECK API
@app.get("/meter-status")
def get_meter_status(meter_id: str, user: dict = Depends(get_current_user)):
    try:
        conn = psycopg2.connect(DB_URL)
        cur = conn.cursor()
        cur.execute("""
            SELECT 
                "LastCommunicationDatetime", 
                "MeterType", 
                "CommunicationMedium", 
                "CTWC"
            FROM "MeterData"
            WHERE "MeterId" = %s
        """, (meter_id,))
        row = cur.fetchone()
        cur.close()
        conn.close()

        if not row:
            raise HTTPException(status_code=404, detail="Meter not found")

        last_comm_str = row[0].strftime("%Y-%m-%d %H:%M:%S")
        last_comm_date = row[0].date()
        status = "communicating" if last_comm_date == date.today() else "noncommunicating"

        return {
            "meter_id": meter_id,
            "status": status,
            "last_communication": last_comm_str,
            "meter_type": row[1],
            "communication_medium": row[2],
            "ctwc": row[3]
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
