from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user_model import (
    PasswordChangeRequest,
    User,
    UserRequest,
    UserLoginRequest,
    UserUpdateRequest
)

from app.auth import (
    CurrentUser,
    create_user_token,
    generate_temporary_password,
    get_active_user,
    get_current_user,
    hash_password,
    require_permission,
    verify_password
)
from app.audit import AuditEventType, AuditOutcome, record_event
from app.demo_seed import demo_mode
from app.permissions import Permission, Role, normalize_role


# =========================================
# EN: Create router
# JP: ルーター作成
# KR: 라우터 생성
# =========================================

router = APIRouter()


# =========================================
# EN: Shared helpers
# JP: 共通ヘルパー
# KR: 공통 헬퍼
# =========================================

def user_to_dict(user: User) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "role": normalize_role(user.role).value,
        "is_active": bool(user.is_active),
        "is_seed": bool(user.is_seed),
        "must_change_password": bool(user.must_change_password),
    }


def find_user_or_404(db: Session, user_id: int) -> User:

    user = db.get(User, user_id)

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    return user


def conflict(detail: str) -> HTTPException:
    return HTTPException(status_code=409, detail=detail)


def username_taken(db: Session, username: str, exclude_id: int = None) -> bool:

    query = db.query(User).filter(User.username == username)

    if exclude_id is not None:
        query = query.filter(User.id != exclude_id)

    return query.first() is not None


def is_active_admin(user: User) -> bool:
    return (
        bool(user.is_active)
        and not user.is_seed
        and normalize_role(user.role) == Role.ADMIN
    )


def is_last_active_admin(db: Session, user: User) -> bool:
    """
    Whether removing this user's admin access would leave no active admin who
    can sign in. Seed accounts never count: they can't sign in. Admin rows are
    locked (SELECT ... FOR UPDATE on PostgreSQL) so two concurrent requests
    can't each remove "the other" last admin.
    """

    if not is_active_admin(user):
        return False

    active_admin_ids = db.query(User.id).filter(
        func.lower(func.trim(User.role)) == Role.ADMIN.value,
        User.is_active.is_(True),
        User.is_seed.is_(False)
    ).with_for_update().all()

    return len(active_admin_ids) <= 1


def ensure_another_active_admin(db: Session, user: User, detail: str):
    """Refuse (409) a change that would leave no active admin."""

    if is_last_active_admin(db, user):
        raise conflict(detail)


def refuse(db: Session, event_type, actor, target, reason: str, detail: str):
    """Audit a safeguard refusal, then respond 409 with the existing message."""

    record_event(
        db, event_type, AuditOutcome.DENIED,
        actor=actor, target=target, details={"reason": reason},
    )
    db.commit()
    raise conflict(detail)


INVALID_CREDENTIALS = HTTPException(
    status_code=401,
    detail="Invalid username or password"
)


def failed_sign_in(db: Session, target, reason: str, method: str):
    # Unknown usernames are not recorded: the typed text could be a password
    # entered in the wrong field.
    record_event(
        db, AuditEventType.SIGN_IN, AuditOutcome.FAILURE,
        target=target, details={"reason": reason, "method": method},
    )
    db.commit()


def authenticate(db: Session, username: str, password: str, method: str) -> User:

    user = db.query(User).filter(
        User.username == username
    ).first()

    if user is None:
        failed_sign_in(db, None, "invalid_credentials", method)
        raise INVALID_CREDENTIALS

    # Seed accounts are demo data only and can never sign in.
    if user.is_seed or not verify_password(password, user.hashed_password):
        failed_sign_in(db, user, "invalid_credentials", method)
        raise INVALID_CREDENTIALS

    # Checked after the password so account status isn't revealed to
    # someone who doesn't know the password.
    if not user.is_active:
        failed_sign_in(db, user, "account_deactivated", method)
        raise HTTPException(
            status_code=403,
            detail="Account is deactivated"
        )

    record_event(
        db, AuditEventType.SIGN_IN, AuditOutcome.SUCCESS,
        actor=user, target=user, details={"method": method},
    )
    db.commit()

    return user


# =========================================
# EN: Create new user (admin only)
# JP: 新規ユーザー作成（管理者のみ）
# KR: 새 사용자 생성 (관리자 전용)
# =========================================

@router.post("/users")
def create_user(
    request: UserRequest,
    response: Response,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(require_permission(Permission.USERS_MANAGE))
):

    if username_taken(db, request.username):
        raise HTTPException(
            status_code=400,
            detail="Username already exists"
        )

    generated = request.password is None
    temporary_password = generate_temporary_password() if generated else request.password

    new_user = User(
        username=request.username,
        hashed_password=hash_password(temporary_password),
        role=request.role,
        is_active=True,
        # In a public demo every account is demo data, which keeps the demo
        # session guard ("no real accounts") intact.
        is_seed=demo_mode(),
        # Admin-issued passwords are always temporary.
        must_change_password=True
    )

    db.add(new_user)
    db.flush()

    record_event(
        db, AuditEventType.USER_CREATED, AuditOutcome.SUCCESS,
        actor=current_user, target=new_user,
        details={"role": new_user.role, "password_generated": generated},
    )

    db.commit()
    db.refresh(new_user)

    # The generated password is returned exactly once and never stored or
    # logged in plain text; stop proxies and browsers caching the response.
    response.headers["Cache-Control"] = "no-store"

    body = {
        "message": "User created",
        "user": user_to_dict(new_user)
    }

    if generated:
        body["temporary_password"] = temporary_password

    return body


# =========================================
# EN: Login user and return JWT token
# JP: ユーザーにログインし、JWTトークンを返す
# KR: 사용자 로그인 후 JWT 토큰 반환
# =========================================

@router.post("/login")
def login_user(
    request: UserLoginRequest,
    db: Session = Depends(get_db)
):

    user = authenticate(db, request.username, request.password, "password")

    return {
        "access_token": create_user_token(user, db),
        "token_type": "bearer"
    }


# =========================================
# EN: OAuth2 login route for Swagger Authorize
# JP: Swagger認証用 OAuth2 ログインルート
# KR: Swagger 인증용 OAuth2 로그인 라우트
# =========================================

@router.post("/token")
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):

    user = authenticate(db, form_data.username, form_data.password, "oauth2_form")

    return {
        "access_token": create_user_token(user, db),
        "token_type": "bearer"
    }


# =========================================
# EN: Protected profile route
# JP: 保護プロフィールルート
# KR: 보호 프로필 라우트
# =========================================

@router.get("/profile")
def get_profile(
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    # Allowed while a password change is pending so the client can prompt
    # for it; `permissions` lets the UI mirror backend rules exactly.
    user = find_user_or_404(db, current_user.id)

    return {
        "message": "Protected profile access granted",
        "user": {
            **user_to_dict(user),
            "permissions": current_user.permissions
        }
    }


# =========================================
# EN: Change own password
# JP: 自分のパスワード変更
# KR: 본인 비밀번호 변경
# =========================================

@router.post("/profile/password")
def change_password(
    request: PasswordChangeRequest,
    current_user: CurrentUser = Depends(get_current_user),
    db: Session = Depends(get_db)
):

    user = find_user_or_404(db, current_user.id)

    # 400 rather than 401: a wrong current password must not end the session.
    def failed(reason: str):
        record_event(
            db, AuditEventType.PASSWORD_CHANGED, AuditOutcome.FAILURE,
            actor=current_user, target=user, details={"reason": reason},
        )
        db.commit()

    if not verify_password(request.current_password, user.hashed_password):
        failed("incorrect_current_password")
        raise HTTPException(
            status_code=400,
            detail="Current password is incorrect"
        )

    if request.new_password == request.current_password:
        failed("password_unchanged")
        raise HTTPException(
            status_code=400,
            detail="New password must be different from the current password"
        )

    user.hashed_password = hash_password(request.new_password)
    user.must_change_password = False

    record_event(
        db, AuditEventType.PASSWORD_CHANGED, AuditOutcome.SUCCESS,
        actor=current_user, target=user,
    )

    db.commit()

    return {
        "message": "Password updated"
    }


# =========================================
# EN: Get all users from PostgreSQL
# JP: PostgreSQL から全ユーザーを取得
# KR: PostgreSQL에서 모든 사용자 조회
# =========================================

@router.get("/users")
def get_users(
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(require_permission(Permission.USERS_READ))
):

    users = db.query(User).order_by(User.id).all()

    return {
        "users": [user_to_dict(user) for user in users]
    }


# =========================================
# EN: Get one user by ID from PostgreSQL
# JP: PostgreSQL からIDでユーザーを1人取得
# KR: PostgreSQL에서 ID로 사용자 1명 조회
# =========================================

@router.get("/users/{user_id}")
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_active_user)
):

    if user_id != current_user.id and not current_user.can(Permission.USERS_READ):
        raise HTTPException(
            status_code=403,
            detail="You don't have permission to perform this action"
        )

    return {
        "user": user_to_dict(find_user_or_404(db, user_id))
    }


# =========================================
# EN: Update user by ID in PostgreSQL
# JP: PostgreSQL 内のユーザーをIDで更新
# KR: PostgreSQL에서 ID로 사용자 수정
# =========================================

@router.put("/users/{user_id}")
def update_user(
    user_id: int,
    request: UserUpdateRequest,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(require_permission(Permission.USERS_MANAGE))
):

    user = find_user_or_404(db, user_id)
    new_role = normalize_role(request.role)
    role_changes = new_role != normalize_role(user.role)

    if role_changes and user.id == current_user.id:
        refuse(db, AuditEventType.ROLE_CHANGED, current_user, user,
               "own_role", "You can't change your own role")

    if role_changes and new_role != Role.ADMIN and is_last_active_admin(db, user):
        refuse(db, AuditEventType.ROLE_CHANGED, current_user, user,
               "last_active_admin", "Cannot remove the last active admin")

    if username_taken(db, request.username, exclude_id=user.id):
        raise HTTPException(
            status_code=400,
            detail="Username already exists"
        )

    old_username = user.username
    old_role = normalize_role(user.role).value

    user.username = request.username
    user.role = new_role.value

    if old_username != user.username:
        record_event(
            db, AuditEventType.USER_UPDATED, AuditOutcome.SUCCESS,
            actor=current_user, target=user,
            details={"from_username": old_username, "to_username": user.username},
        )

    if role_changes:
        record_event(
            db, AuditEventType.ROLE_CHANGED, AuditOutcome.SUCCESS,
            actor=current_user, target=user,
            details={"from_role": old_role, "to_role": new_role.value},
        )

    db.commit()
    db.refresh(user)

    return {
        "message": "User updated",
        "user": user_to_dict(user)
    }


# =========================================
# EN: Deactivate / reactivate (the normal way to remove access)
# JP: 無効化 / 再有効化（通常のアクセス削除方法）
# KR: 비활성화 / 재활성화 (일반적인 접근 제거 방법)
# =========================================

@router.post("/users/{user_id}/deactivate")
def deactivate_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(require_permission(Permission.USERS_MANAGE))
):

    user = find_user_or_404(db, user_id)

    if user.id == current_user.id:
        refuse(db, AuditEventType.USER_DEACTIVATED, current_user, user,
               "own_account", "You can't deactivate your own account")

    if is_last_active_admin(db, user):
        refuse(db, AuditEventType.USER_DEACTIVATED, current_user, user,
               "last_active_admin", "Cannot deactivate the last active admin")

    user.is_active = False

    record_event(
        db, AuditEventType.USER_DEACTIVATED, AuditOutcome.SUCCESS,
        actor=current_user, target=user,
    )

    db.commit()
    db.refresh(user)

    return {
        "message": "User deactivated",
        "user": user_to_dict(user)
    }


@router.post("/users/{user_id}/reactivate")
def reactivate_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(require_permission(Permission.USERS_MANAGE))
):

    user = find_user_or_404(db, user_id)
    user.is_active = True

    record_event(
        db, AuditEventType.USER_REACTIVATED, AuditOutcome.SUCCESS,
        actor=current_user, target=user,
    )

    db.commit()
    db.refresh(user)

    return {
        "message": "User reactivated",
        "user": user_to_dict(user)
    }


# =========================================
# EN: Permanently delete a deactivated user
# JP: 無効化済みユーザーを完全に削除
# KR: 비활성화된 사용자를 영구 삭제
# =========================================

@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(require_permission(Permission.USERS_MANAGE))
):

    user = find_user_or_404(db, user_id)

    if user.id == current_user.id:
        refuse(db, AuditEventType.USER_DELETED, current_user, user,
               "own_account", "You can't delete your own account")

    # Deletion is a separate, deliberate second step after deactivation, which
    # also guarantees an active admin can never be deleted.
    if user.is_active:
        refuse(db, AuditEventType.USER_DELETED, current_user, user,
               "still_active", "Deactivate the user before deleting them permanently")

    deleted_user = user_to_dict(user)

    # The event keeps a snapshot of the deleted account's id and username.
    record_event(
        db, AuditEventType.USER_DELETED, AuditOutcome.SUCCESS,
        actor=current_user, target=user,
        details={"role": normalize_role(user.role).value},
    )

    db.delete(user)
    db.commit()

    return {
        "message": "User deleted",
        "deleted_user": deleted_user
    }
