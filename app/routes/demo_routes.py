from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import create_user_token
from app.database import get_db
from app.demo_seed import DEMO_GUIDE_USERNAME, demo_mode
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
    Sign in to the public demo without credentials.

    Only exists when APP_ENV=demo (404 everywhere else) and refuses to issue a
    token while the database contains any non-demo account, so it can never
    be used against a database holding real users.
    """

    if not demo_mode():
        raise HTTPException(status_code=404, detail="Not Found")

    real_accounts = db.query(User).filter(User.is_seed.is_(False)).count()

    if real_accounts:
        raise HTTPException(
            status_code=503,
            detail="Demo sessions are disabled: this database contains non-demo accounts"
        )

    guide = db.query(User).filter(
        User.username == DEMO_GUIDE_USERNAME,
        User.is_seed.is_(True),
        User.is_active.is_(True)
    ).first()

    if guide is None:
        raise HTTPException(
            status_code=503,
            detail="Demo environment is not seeded"
        )

    return {
        "access_token": create_user_token(guide),
        "token_type": "bearer"
    }
