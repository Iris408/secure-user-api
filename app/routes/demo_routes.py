from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.audit import AuditEventType, AuditOutcome, record_event
from app.auth import create_user_token
from app.database import get_db
from app.demo_seed import DEMO_ADMIN_USERNAME, demo_mode
from app.models.user_model import User


# =========================================
# EN: Public demo sessions (isolated demo deployments only)
# JP: 公開デモセッション（分離されたデモ環境のみ）
# KR: 공개 데모 세션 (격리된 데모 환경 전용)
# =========================================

router = APIRouter()


@router.post("/demo/session", include_in_schema=False)
def start_demo_session(db: Session = Depends(get_db)):
    """
    Sign in to the public demo as adminDemoUser, without credentials.

    Only exists when APP_ENV=demo (404 everywhere else) and refuses to issue a
    token while the database contains any non-demo account, so it can never
    be used against a database holding real users.
    """

    if not demo_mode():
        raise HTTPException(status_code=404, detail="Not Found")

    real_accounts = db.query(User).filter(User.is_seed.is_(False)).count()

    if real_accounts:
        record_event(
            db, AuditEventType.DEMO_SESSION, AuditOutcome.DENIED,
            details={"reason": "real_accounts_present"},
        )
        db.commit()
        raise HTTPException(
            status_code=503,
            detail="Demo sessions are disabled: this database contains non-demo accounts"
        )

    demo_admin = db.query(User).filter(
        User.username == DEMO_ADMIN_USERNAME,
        User.is_seed.is_(True),
        User.is_active.is_(True)
    ).first()

    if demo_admin is None:
        raise HTTPException(
            status_code=503,
            detail="Demo environment is not seeded"
        )

    record_event(
        db, AuditEventType.DEMO_SESSION, AuditOutcome.SUCCESS,
        actor=demo_admin, details={"method": "demo_session"},
    )
    db.commit()

    return {
        "access_token": create_user_token(demo_admin, db),
        "token_type": "bearer"
    }
