import os

from urllib.parse import urlparse

import pytest

# Must be set before the app is imported (bcrypt cost is read at import time).
os.environ.setdefault("APP_ENV", "test")

# app.database only builds a lazy engine, so this import doesn't connect.
from app.database import DATABASE_URL  # noqa: E402

# Importing app.main creates tables and the fixtures below drop them, so stop
# before anything connects unless this is clearly a test database.
_database_name = urlparse(DATABASE_URL).path.lstrip("/")

if "test" not in _database_name:
    pytest.exit(
        "Refusing to run tests: DATABASE_URL must point to a database "
        f"whose name contains 'test' (got '{_database_name}')",
        returncode=2,
    )

from fastapi.testclient import TestClient  # noqa: E402

from app.auth import hash_password  # noqa: E402
from app.database import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.migrations import (  # noqa: E402
    ensure_audit_log_append_only,
    ensure_role_permission_defaults,
    ensure_settings_row,
    run_migrations,
)
from app.models.access_request_model import AccessRequest  # noqa: E402,F401
from app.models.audit_model import AuditEvent  # noqa: E402,F401
from app.models.role_permission_model import RolePermissionGrant  # noqa: E402,F401
from app.models.settings_model import OrganisationSettings  # noqa: E402,F401
from app.models.user_model import User  # noqa: E402


PASSWORD = "correct-horse-battery"


@pytest.fixture(autouse=True)
def clean_database():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    run_migrations(engine)
    ensure_audit_log_append_only(engine)
    ensure_role_permission_defaults(engine)
    ensure_settings_row(engine)
    yield


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def db():
    with SessionLocal() as session:
        yield session


@pytest.fixture
def make_user(db):

    def factory(
        username,
        role="member",
        *,
        password=PASSWORD,
        is_active=True,
        is_seed=False,
        must_change_password=False,
    ):
        user = User(
            username=username,
            hashed_password=hash_password(password),
            role=role,
            is_active=is_active,
            is_seed=is_seed,
            must_change_password=must_change_password,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    return factory


@pytest.fixture
def login(client):

    def do(username, password=PASSWORD):
        response = client.post(
            "/login",
            json={"username": username, "password": password},
        )
        assert response.status_code == 200, response.text
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    return do
