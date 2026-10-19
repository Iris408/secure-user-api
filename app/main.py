from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.database import engine, Base, get_db
from app.migrations import run_migrations
from app.models.user_model import User  # noqa: F401 - registers the table
from app.routes.demo_routes import router as demo_router
from app.routes.user_routes import router as user_router

from sqlalchemy import text
from sqlalchemy.orm import Session


app = FastAPI(
    title="Secure User Management API",
    description=(
        "A production-style API for authentication, "
        "user management and role-based access control."
    ),
    version="1.0.0",
)

# EN: Allow frontend apps to call this backend API
# JP: フロントエンドアプリがこのバックエンドAPIを呼び出せるようにする

origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",

    "http://localhost:5175",
    "http://127.0.0.1:5175",
    "http://192.0.0.2:5175",

    "https://jwt-authentication-dashboard-sepia.vercel.app",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)

# EN: Bring existing tables up to date (additive, idempotent)
# JP: 既存テーブルを最新化（追加のみ・冪等）
# KR: 기존 테이블을 최신화 (추가 전용, 멱등)
run_migrations(engine)

app.include_router(user_router)
app.include_router(demo_router)

@app.get("/")
def root():
    return {
        "message": "Secure User Management API is running",
        "status": "ok",
        "docs": "/docs"
    }

@app.get("/health")
def health_check():
    return {
        "status": "ok", 
        "service": "secure-user-management-api"
    }

@app.get("/ready")
def readiness_check(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {
            "status": "ready",
            "database": "connected",
            "service": "secure-user-management-api"
        }
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Database unavailable"
        )
