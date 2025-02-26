import os
import uuid
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import Column, String, Integer, ForeignKey, TIMESTAMP, func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from dotenv import load_dotenv
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
import uuid

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL is not set in environment variables")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class UserDB(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    referral_token = Column(String, unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    referred_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    referrals = relationship("Referral", foreign_keys="[Referral.referrer_id]", back_populates="referrer")

class Referral(Base):
    __tablename__ = "referrals"

    id = Column(Integer, primary_key=True, index=True)
    referrer_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    referred_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(TIMESTAMP, server_default=func.now())

    referrer = relationship("UserDB", foreign_keys=[referrer_id], back_populates="referrals")
    referred = relationship("UserDB", foreign_keys=[referred_id])

Base.metadata.create_all(bind=engine)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
app = FastAPI()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_user(db, username: str):
    return db.query(UserDB).filter(UserDB.username == username).first()

def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

class UserCreate(BaseModel):
    username: str
    email: str
    full_name: str
    password: str
    referral_token: Optional[str] = None

import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)



@app.post("/signup")
def signup(user: UserCreate, db: Session = Depends(get_db)):
    hashed_password = get_password_hash(user.password)
    new_referral_token = str(uuid.uuid4())
    referred_by = None

    # Debugging print

    if user.referral_token:
        referrer = db.query(UserDB).filter(UserDB.referral_token == user.referral_token).first()
        if referrer:
            referred_by = referrer.id
        else:
            raise HTTPException(status_code=400, detail="Invalid referral token")
        
    
    print(f"Received referral token: {user.referral_token}")
    print(f"Referrer found: {referred_by}")

    # Create user object
    db_user = UserDB(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        hashed_password=hashed_password,
        referral_token=new_referral_token,
        referred_by=referred_by,
    )

    try:
        db.add(db_user)
        db.commit()
        db.refresh(db_user)

        # If the user was referred, add a referral record
        if referred_by:
            referral = Referral(referrer_id=referred_by, referred_id=db_user.id)
            db.add(referral)
            db.commit()

        return {"message": "User created successfully", "referral_token": new_referral_token}

    except IntegrityError as e:
        db.rollback()
        raise HTTPException(status_code=400, detail="User already exists or database error")

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")



class Token(BaseModel):
    access_token: str
    token_type: str

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: SessionLocal = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

# Run with Render-assigned port
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, port=port)