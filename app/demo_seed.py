import os
import random
import secrets

from urllib.parse import urlparse

from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from app.auth import hash_password
from app.models.user_model import User
from app.permissions import Role


# =========================================
# EN: Synthetic demo/test users (never for production)
# JP: デモ/テスト用の合成ユーザー（本番環境では使用しない）
# KR: 데모/테스트용 합성 사용자 (운영 환경 사용 금지)
# =========================================
#
# Safeguards:
# - Refuses to run unless APP_ENV is development, test or demo.
# - Refuses Render targets (RENDER env var or a *.render.com database host) by
#   default. The only exception is the dedicated demo database, and only when
#   ALL of these hold: APP_ENV=demo, the --allow-render-demo flag, an
#   --expected-database name matching current_database(), and no non-seed
#   user rows in that database. See verify_demo_database().
# - Every account is marked is_seed=true and named "demo.<first>.<last>" so it
#   is clearly distinguishable from real accounts in the API and the UI.
# - Seed accounts share a hash of a random, discarded secret and the login
#   route rejects is_seed users, so they can never be used to sign in.
# - Seed admins are ignored by the "last active admin" safeguard.
# - Removal only ever deletes rows with is_seed=true.
#
# Public demo (APP_ENV=demo only):
# - A separate "adminDemoUser" seed account (demo admin) backs
#   POST /demo/session. It has no usable password; the endpoint issues its
#   token instead. An existing non-seed account with that name is never
#   modified.
# - The endpoint refuses to run while the database holds any non-seed account,
#   so public demo access can never reach a database with real users. Users
#   created during a demo are themselves stored as seed data.

SEED_COUNT = 124
SEED_PREFIX = "demo."
DEMO_ADMIN_USERNAME = "adminDemoUser"
ALLOWED_ENVIRONMENTS = {"development", "test", "demo"}

ROLE_COUNTS = {
    Role.ADMIN: 6,
    Role.MANAGER: 18,
    Role.VIEWER: 20,
    # Remaining accounts are members.
}
INACTIVE_EVERY = 15

FIRST_NAMES = [
    "alex", "ava", "ben", "chloe", "daniel", "emily", "farah", "george",
    "hana", "isaac", "jade", "kenji", "lucia", "marcus", "nina", "omar",
    "priya", "quinn", "rosa", "sam", "tara", "umar", "vera", "wei",
    "yuki", "zoe",
]
LAST_NAMES = [
    "carter", "chen", "garcia", "kim", "lewis", "martin", "patel",
    "rodriguez", "sato", "thompson",
]


class SeedNotAllowed(RuntimeError):
    pass


def demo_mode(environ=None) -> bool:
    """True only for an isolated public demo deployment (APP_ENV=demo)."""
    environ = os.environ if environ is None else environ
    return environ.get("APP_ENV", "").strip().lower() == "demo"


def is_render_target(environ=None) -> bool:
    """Running on Render, or pointed at a Render-hosted database."""
    environ = os.environ if environ is None else environ
    host = urlparse(environ.get("DATABASE_URL", "")).hostname or ""
    return bool(environ.get("RENDER")) or host.endswith(".render.com")


def assert_seed_allowed(environ=None, allow_render_demo: bool = False) -> None:
    """
    Environment checks that need no database connection. Render targets also
    need verify_demo_database() to pass before anything is written.
    """

    environ = os.environ if environ is None else environ
    app_env = environ.get("APP_ENV", "").strip().lower()

    if app_env not in ALLOWED_ENVIRONMENTS:
        raise SeedNotAllowed(
            "Demo seed data can only be created when APP_ENV is one of "
            f"{', '.join(sorted(ALLOWED_ENVIRONMENTS))} (current: {app_env or 'unset'})"
        )

    if not is_render_target(environ):
        return

    if not allow_render_demo:
        raise SeedNotAllowed(
            "Refusing to seed demo data on Render. Seeding the dedicated demo "
            "database requires APP_ENV=demo, --allow-render-demo and "
            "--expected-database"
        )

    if app_env != "demo":
        raise SeedNotAllowed(
            f"Render demo seeding requires APP_ENV=demo (current: {app_env})"
        )


def count_non_seed_users(db: Session) -> int:
    """Rows that are not demo data. Every row counts on a legacy schema."""

    inspector = inspect(db.get_bind())

    if not inspector.has_table("users"):
        return 0

    columns = {column["name"] for column in inspector.get_columns("users")}

    if "is_seed" not in columns:
        return db.execute(text("SELECT COUNT(*) FROM users")).scalar_one()

    return db.execute(
        text("SELECT COUNT(*) FROM users WHERE is_seed IS NOT TRUE")
    ).scalar_one()


def verify_demo_database(db: Session, expected_database) -> None:
    """
    Confirm the connection really is the dedicated, empty-of-real-users demo
    database. Run before creating tables or writing anything.
    """

    if not expected_database:
        raise SeedNotAllowed(
            "--expected-database is required: name the dedicated demo database"
        )

    actual = db.execute(text("SELECT current_database()")).scalar_one()

    if actual != expected_database:
        raise SeedNotAllowed(
            f"Connected to database '{actual}', not the expected "
            f"'{expected_database}'"
        )

    real_accounts = count_non_seed_users(db)

    if real_accounts:
        raise SeedNotAllowed(
            f"Database '{actual}' contains {real_accounts} non-seed user "
            "record(s); demo data is only seeded into a database without real "
            "accounts"
        )


def demo_usernames(count: int = SEED_COUNT) -> list:
    names = [
        f"{SEED_PREFIX}{first}.{last}"
        for last in LAST_NAMES
        for first in FIRST_NAMES
    ]

    if count > len(names):
        raise ValueError(f"At most {len(names)} demo users are supported")

    return names[:count]


def demo_roles(count: int = SEED_COUNT) -> list:
    roles = []

    for role, amount in ROLE_COUNTS.items():
        roles.extend([role] * amount)

    roles.extend([Role.MEMBER] * max(0, count - len(roles)))

    # Fixed seed: the same usernames always get the same roles.
    random.Random(2026).shuffle(roles)
    return roles[:count]


def seed_demo_users(
    db: Session,
    count: int = SEED_COUNT,
    environ=None,
    allow_render_demo: bool = False,
) -> int:
    """
    Create missing demo users. Existing accounts with the same names are
    skipped, never modified. Returns how many were created.
    """

    assert_seed_allowed(environ, allow_render_demo)

    existing = {
        username
        for (username,) in db.query(User.username).filter(
            User.username.like(f"{SEED_PREFIX}%")
        )
    }

    # One hash of a random secret that is immediately discarded.
    unusable_hash = hash_password(secrets.token_urlsafe(32))
    created = 0

    for index, (username, role) in enumerate(
        zip(demo_usernames(count), demo_roles(count)), start=1
    ):
        if username in existing:
            continue

        db.add(User(
            username=username,
            hashed_password=unusable_hash,
            role=role.value,
            is_active=index % INACTIVE_EVERY != 0,
            is_seed=True,
            must_change_password=False,
        ))
        created += 1

    db.commit()
    return created


def remove_demo_users(db: Session, environ=None, allow_render_demo: bool = False) -> int:
    """Delete every is_seed user and nothing else. Returns how many."""

    assert_seed_allowed(environ, allow_render_demo)

    removed = db.query(User).filter(User.is_seed.is_(True)).delete(
        synchronize_session=False
    )
    db.commit()
    return removed


def ensure_demo_admin(db: Session, environ=None, allow_render_demo: bool = False) -> bool:
    """
    Create adminDemoUser, the demo admin behind public demo sessions. It is
    seed data, so it can't sign in with a password and is removed with the
    other demo users. Returns True when it was created.
    """

    assert_seed_allowed(environ, allow_render_demo)

    existing = db.query(User).filter(User.username == DEMO_ADMIN_USERNAME).first()

    if existing is not None:
        if not existing.is_seed:
            # Never take over or modify a real account.
            raise SeedNotAllowed(
                f"A non-seed account named '{DEMO_ADMIN_USERNAME}' already exists"
            )
        return False

    db.add(User(
        username=DEMO_ADMIN_USERNAME,
        hashed_password=hash_password(secrets.token_urlsafe(32)),
        role=Role.ADMIN.value,
        is_active=True,
        is_seed=True,
        must_change_password=False,
    ))
    db.commit()
    return True
