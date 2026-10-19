import re
from typing import Optional

from pydantic import BaseModel, field_validator
from sqlalchemy import Boolean, Column, Integer, String, false, true

from app.database import Base
from app.permissions import parse_role


USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{3,50}$")
PASSWORD_MIN_LENGTH = 12
# bcrypt only uses the first 72 bytes of a password
PASSWORD_MAX_BYTES = 72


def validate_username(value: str) -> str:
    value = value.strip()

    if not USERNAME_PATTERN.match(value):
        raise ValueError(
            "Username must be 3-50 characters: letters, numbers, '.', '_' or '-'"
        )

    return value


def validate_password(value: str) -> str:
    if len(value) < PASSWORD_MIN_LENGTH:
        raise ValueError(
            f"Password must be at least {PASSWORD_MIN_LENGTH} characters"
        )

    if len(value.encode("utf-8")) > PASSWORD_MAX_BYTES:
        raise ValueError(f"Password must be at most {PASSWORD_MAX_BYTES} bytes")

    return value


def validate_role(value: str) -> str:
    return parse_role(value).value


# =========================================
# EN: Request model for creating a user
# JP: ユーザー作成用リクエストモデル
# KR: 사용자 생성 요청 모델
# =========================================

class UserRequest(BaseModel):
    username: str
    # Optional: when omitted the server generates a one-time temporary
    # password. Either way the user must change it at first sign-in.
    password: Optional[str] = None
    role: str = "member"

    _check_username = field_validator("username")(validate_username)
    _check_role = field_validator("role")(validate_role)

    @field_validator("password")
    @classmethod
    def _check_password(cls, value):
        return None if value is None else validate_password(value)


class UserLoginRequest(BaseModel):
    username: str
    password: str


# =========================================
# EN: Request model for updating a user
# JP: ユーザー更新用リクエストモデル
# KR: 사용자 수정 요청 모델
# =========================================

class UserUpdateRequest(BaseModel):
    username: str
    role: str = "member"

    _check_username = field_validator("username")(validate_username)
    _check_role = field_validator("role")(validate_role)


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str

    _check_new_password = field_validator("new_password")(validate_password)


# =========================================
# EN: SQLAlchemy database model for users table
# JP: users テーブル用 SQLAlchemy データベースモデル
# KR: users 테이블용 SQLAlchemy 데이터베이스 모델
# =========================================

class User(Base):

    __tablename__ = "users"

    # EN: Unique user ID
    # JP: 一意のユーザーID
    # KR: 고유 사용자 ID
    id = Column(Integer, primary_key=True, index=True)

    # EN: Username used for login
    # JP: ログイン用ユーザー名
    # KR: 로그인용 사용자 이름
    username = Column(String, unique=True, index=True)

    # EN: Hashed password stored safely
    # JP: 安全に保存されるハッシュ化パスワード
    # KR: 안전하게 저장되는 해시된 비밀번호
    hashed_password = Column(String)

    # EN: Role: admin, manager, member or viewer. Legacy rows may still hold
    #     "user" or "Admin"; app.permissions.normalize_role maps them.
    # JP: ロール。旧データの "user" / "Admin" は normalize_role で変換
    # KR: 역할. 기존 "user" / "Admin" 값은 normalize_role 로 변환
    role = Column(String, default="member")

    # EN: Deactivated users cannot sign in and their tokens stop working
    # JP: 無効化されたユーザーはサインインできない
    # KR: 비활성화된 사용자는 로그인할 수 없음
    is_active = Column(Boolean, nullable=False, default=True, server_default=true())

    # EN: Synthetic demo/test account created by scripts/seed_demo_users.py
    # JP: デモ/テスト用の合成アカウント
    # KR: 데모/테스트용 합성 계정
    is_seed = Column(Boolean, nullable=False, default=False, server_default=false())

    # EN: Set for admin-issued temporary passwords
    # JP: 管理者が発行した一時パスワードの場合に設定
    # KR: 관리자가 발급한 임시 비밀번호인 경우 설정
    must_change_password = Column(
        Boolean, nullable=False, default=False, server_default=false()
    )
