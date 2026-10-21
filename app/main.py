from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.database import engine, Base, get_db
from app.migrations import (
    ensure_audit_log_append_only,
    ensure_role_permission_defaults,
    ensure_settings_row,
    run_migrations,
)
from app.models.access_request_model import AccessRequest  # noqa: F401 - registers the table
from app.models.audit_model import AuditEvent  # noqa: F401 - registers the table
from app.models.role_permission_model import RolePermissionGrant  # noqa: F401 - registers the table
from app.models.settings_model import OrganisationSettings  # noqa: F401 - registers the table
from app.models.user_model import User
from app.routes.access_request_routes import router as access_request_router
from app.routes.activity_routes import router as activity_router
from app.routes.audit_routes import router as audit_router
from app.routes.demo_routes import router as demo_router
from app.routes.role_permission_routes import router as role_permission_router
from app.routes.settings_routes import router as settings_router
from app.routes.user_routes import router as user_router

from sqlalchemy import text
from sqlalchemy.orm import Session


app = FastAPI(
    title="AccessHub API",
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
    "https://accesshub-7jy6awsnz-iris408.vercel.app",
    "https://accesshub-iris408.vercel.app",

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
ensure_audit_log_append_only(engine)
ensure_role_permission_defaults(engine)
ensure_settings_row(engine)

app.include_router(user_router)
app.include_router(demo_router)
app.include_router(audit_router)
app.include_router(access_request_router)
app.include_router(role_permission_router)
app.include_router(activity_router)
app.include_router(settings_router)

@app.get("/")
def root():
    return {
        "message": "AccessHub API is running",
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
