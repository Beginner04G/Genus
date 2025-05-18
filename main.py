from fastapi import FastAPI, HTTPException, Depends, Security, Form
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
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2PasswordRequestForm

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
DB_URL1 = os.getenv("DB_URL1")
DB_URL3 = os.getenv("DB_URL3")

# ✅ AUTH CONFIG
SECRET_KEY = os.getenv("SECRET_KEY")
print("DB_URL1:", DB_URL1)
print("DB_URL3:", DB_URL3)
print("SECRET_KEY:", SECRET_KEY)

# Password hashing configuration
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)

def create_tables(db_url):
    try:
        with closing(psycopg2.connect(db_url)) as conn:
            with conn.cursor() as cur:
                # Create users table if it doesn't exist
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS "users" (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(50) UNIQUE NOT NULL,
                        email VARCHAR(100) UNIQUE NOT NULL,
                        password VARCHAR(255) NOT NULL
                    )
                """)
                # Create meter data table if it doesn't exist
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS "MeterData" (
                        "MeterId" VARCHAR(50) PRIMARY KEY,
                        "LastCommunicationDatetime" TIMESTAMP,
                        "MeterType" VARCHAR(50),
                        "CommunicationMedium" VARCHAR(50),
                        "CTWC" VARCHAR(20)
                    )
                """)
                conn.commit()
    except Exception as e:
        print(f"Error creating tables for {db_url}:", str(e))

# Create tables in both databases
create_tables(DB_URL1)
create_tables(DB_URL3)

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

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


# Refresh token config
REFRESH_TOKEN_EXPIRE_DAYS = 7
refresh_tokens_store = {}  # In-memory store: {refresh_token: user_email}

# Utility to create refresh token
def create_refresh_token(data: dict):
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ✅ SIGNUP API
@app.get("/")
def read_root():
    return {"message": "FastAPI is running"}

@app.post("/signup")
def signup(user: SignupModel):
    try:
        with closing(psycopg2.connect(DB_URL1)) as conn:
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
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        conn = psycopg2.connect(DB_URL1)
        cur = conn.cursor()
        cur.execute('SELECT id, username, password FROM "users" WHERE email = %s', (form_data.username,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if not user or not verify_password(form_data.password, user[2]):
            raise HTTPException(status_code=401, detail="Invalid email or password")

        token = create_token({"sub": form_data.username})
        refresh_token = create_refresh_token({"sub": form_data.username})
        # Store refresh token in memory (for demo; use DB in production)
        refresh_tokens_store[refresh_token] = form_data.username

        return {
            "access_token": token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "username": user[1],
            "user_id": user[0]
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Endpoint to refresh access token
class RefreshTokenRequest(BaseModel):
    refresh_token: str

@app.post("/refresh-token")
def refresh_token_endpoint(request: RefreshTokenRequest):
    refresh_token = request.refresh_token
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        user_email = payload.get("sub")
        # Check if refresh token is valid and present in store
        if refresh_tokens_store.get(refresh_token) != user_email:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        # Optionally: remove used refresh token to prevent reuse (rotate)
        # del refresh_tokens_store[refresh_token]
        new_access_token = create_token({"sub": user_email})
        return {"access_token": new_access_token, "token_type": "bearer"}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")


# ✅ METER CHECK API
@app.get("/meter-status")
def get_meter_status(meter_id: str, package: str = "PKG1", user: dict = Depends(get_current_user)):
    try:
        # Select database based on package
        db_url = DB_URL3 if package == "PKG3" else DB_URL1
        
        conn = psycopg2.connect(db_url)
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
