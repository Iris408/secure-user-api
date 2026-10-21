import os
import secrets

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.audit import AuditEventType, AuditOutcome, record_event
from app.database import get_db
from app.models.user_model import User
from app.permissions import Permission, normalize_role
from app.policy import resolve_permissions
from app.settings import load_settings


load_dotenv()


# =========================================
# EN: OAuth2 token scheme for protected routes
# JP: 保護ルート用 OAuth2 トークンスキーム
# KR: 보호된 라우트용 OAuth2 토큰 스키마
# =========================================

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token"
)


# =========================================
# EN: Password hashing configuration
# JP: パスワードハッシュ設定
# KR: 비밀번호 해시 설정
# =========================================

def _bcrypt_rounds() -> int:
    # Fewer rounds keep the test suite fast; never configurable elsewhere.
    if os.getenv("APP_ENV") == "test":
        return int(os.getenv("BCRYPT_ROUNDS", "4"))
    return 12


pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=_bcrypt_rounds(),
)


# =========================================
# EN: Hash password
# JP: パスワードハッシュ化
# KR: 비밀번호 해시화
# =========================================

def hash_password(password: str):

    return pwd_context.hash(password)


# =========================================
# EN: Verify password
# JP: パスワード確認
# KR: 비밀번호 확인
# =========================================

def verify_password(
    plain_password: str,
    hashed_password: str
):

    try:
        return pwd_context.verify(
            plain_password,
            hashed_password
        )
    except (ValueError, TypeError):
        # Unknown or missing hash: treat as a failed login, never a 500.
        return False


# =========================================
# EN: One-time temporary password for admin-created accounts
# JP: 管理者が作成したアカウント用の一時パスワード
# KR: 관리자가 만든 계정용 임시 비밀번호
# =========================================

def generate_temporary_password() -> str:
    # 18 random bytes -> 24 URL-safe characters (~144 bits of entropy)
    return secrets.token_urlsafe(18)


# =========================================
# EN: JWT configuration
# JP: JWT 設定
# KR: JWT 설정
# =========================================

INSECURE_DEFAULT_KEY = "temporary_secret_key_change_later"
LOCAL_ENVIRONMENTS = {"development", "test"}


class InsecureConfiguration(RuntimeError):
    pass


def load_secret_key(environ=None) -> str:
    """
    The JWT signing key. Anything other than development/test — including an
    unset APP_ENV, which is treated as production — must configure its own
    SECRET_KEY; the app refuses to start rather than sign tokens with a
    publicly known key.
    """

    environ = os.environ if environ is None else environ
    key = (environ.get("SECRET_KEY") or "").strip()
    app_env = (environ.get("APP_ENV") or "").strip().lower()

    if app_env in LOCAL_ENVIRONMENTS:
        return key or INSECURE_DEFAULT_KEY

    if not key or key == INSECURE_DEFAULT_KEY:
        raise InsecureConfiguration(
            "SECRET_KEY must be set to a private random value "
            f"(APP_ENV is '{app_env or 'unset'}', treated as production)"
        )

    return key


SECRET_KEY = load_secret_key()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# =========================================
# EN: Create JWT access token
# JP: JWT アクセストークン作成
# KR: JWT 액세스 토큰 생성
# =========================================

def create_access_token(data: dict, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES):

    token_data = data.copy()

    expire = datetime.now(timezone.utc) + timedelta(
        minutes=expires_minutes
    )

    token_data.update(
        {
            "exp": expire
        }
    )

    encoded_jwt = jwt.encode(
        token_data,
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    return encoded_jwt


def create_user_token(user: User, db: Session) -> str:
    # `uid` lets the token survive a username change; `role` is informational
    # only — permissions are always re-read from the database. The lifetime is
    # the organisation's session setting at sign-in; a token keeps the expiry
    # it was issued with, so a change applies to new sessions.
    return create_access_token(
        data={
            "sub": user.username,
            "uid": user.id,
            "role": normalize_role(user.role).value,
        },
        expires_minutes=load_settings(db).session_minutes,
    )


# =========================================
# EN: Verify JWT token
# JP: JWT トークン確認
# KR: JWT 토큰 검증
# =========================================

def verify_token(token: str):

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        username = payload.get("sub")

        if username is None:
            return None

        return {
            "username": username,
            "uid": payload.get("uid"),
            "role": payload.get("role")
        }

    except JWTError:
        return None


# =========================================
# EN: Current authenticated user
# JP: 現在の認証ユーザー
# KR: 현재 인증 사용자
# =========================================

@dataclass(frozen=True)
class CurrentUser:
    id: int
    username: str
    role: str
    must_change_password: bool
    # Resolved from the persisted policy when the request is authenticated.
    granted: frozenset = frozenset()

    @property
    def permissions(self) -> list:
        return sorted(permission.value for permission in self.granted)

    def can(self, permission: Permission) -> bool:
        return permission in self.granted


INVALID_TOKEN = HTTPException(
    status_code=401,
    detail="Invalid or expired token"
)


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> CurrentUser:
    """
    Resolve the token to a live, active database user. Role and status come
    from the database on every request, so deactivation, deletion and role
    changes take effect immediately rather than when the token expires.
    """

    token_data = verify_token(token)

    if token_data is None:
        raise INVALID_TOKEN

    if token_data["uid"] is not None:
        user = db.get(User, token_data["uid"])
    else:
        # Tokens issued before `uid` was added identify users by username.
        user = db.query(User).filter(
            User.username == token_data["username"]
        ).first()

    if user is None or not user.is_active:
        raise INVALID_TOKEN

    role = normalize_role(user.role)

    return CurrentUser(
        id=user.id,
        username=user.username,
        role=role.value,
        must_change_password=bool(user.must_change_password),
        # Current policy for the current database role, on every request.
        granted=resolve_permissions(db, role),
    )


def get_active_user(
    current_user: CurrentUser = Depends(get_current_user)
) -> CurrentUser:
    """Like get_current_user, but blocks accounts with a pending password change."""

    if current_user.must_change_password:
        raise HTTPException(
            status_code=403,
            detail="Password change required"
        )

    return current_user


# =========================================
# EN: Permission checker
# JP: 権限確認
# KR: 권한 확인
# =========================================

FORBIDDEN_DETAIL = "You don't have permission to perform this action"


def route_label(request: Request) -> str:
    """'METHOD /path/{param}' — the route template, never raw IDs or queries."""
    route = request.scope.get("route")
    path = getattr(route, "path", None) or request.url.path
    return f"{request.method} {path}"


def deny_access(
    db: Session,
    request: Request,
    current_user: CurrentUser,
    permission: Permission,
    reason: str = "missing_permission",
):
    """Record an access.denied audit event, then refuse with 403."""

    record_event(
        db,
        AuditEventType.ACCESS_DENIED,
        AuditOutcome.DENIED,
        actor=current_user,
        details={
            "permission": permission.value,
            "action": route_label(request),
            "reason": reason,
        },
    )
    db.commit()

    raise HTTPException(status_code=403, detail=FORBIDDEN_DETAIL)


def require_permission(permission: Permission):

    def dependency(
        request: Request,
        current_user: CurrentUser = Depends(get_active_user),
        db: Session = Depends(get_db),
    ):

        # Signed-in users reaching a route they lack permission for is a
        # security-relevant event (the UI never offers these actions), so it
        # is audited.
        if not current_user.can(permission):
            deny_access(db, request, current_user, permission)

        return current_user

    return dependency
