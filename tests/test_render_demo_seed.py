from collections import Counter
from urllib.parse import urlparse

import pytest
from sqlalchemy import text

from app.database import DATABASE_URL, Base, engine
from app.demo_seed import (
    DEMO_ADMIN_USERNAME,
    SeedNotAllowed,
    assert_seed_allowed,
    count_non_seed_users,
    ensure_demo_admin,
    verify_demo_database,
)
from app.models.user_model import User
from scripts import seed_demo_users as seed_cli
from tests.conftest import PASSWORD


TEST_DATABASE = urlparse(DATABASE_URL).path.lstrip("/")
RENDER_DB_URL = "postgresql://u:p@dpg-abc.oregon-postgres.render.com/accesshub_demo"


@pytest.fixture
def render_demo_env(monkeypatch):
    """Simulate running on Render as the demo deployment."""
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.setenv("APP_ENV", "demo")


def run_cli(*args):
    return seed_cli.main(list(args))


# =========================================
# Default refusal and each opt-in requirement
# =========================================

@pytest.mark.parametrize(
    "environ",
    [
        {"APP_ENV": "demo", "RENDER": "true"},
        {"APP_ENV": "demo", "DATABASE_URL": RENDER_DB_URL},
        {"APP_ENV": "development", "RENDER": "true"},
    ],
)
def test_render_targets_are_refused_by_default(environ):
    with pytest.raises(SeedNotAllowed, match="Refusing to seed demo data on Render"):
        assert_seed_allowed(environ)


@pytest.mark.parametrize("app_env", ["development", "test"])
def test_render_opt_in_requires_app_env_demo(app_env):
    with pytest.raises(SeedNotAllowed, match="requires APP_ENV=demo"):
        assert_seed_allowed(
            {"APP_ENV": app_env, "DATABASE_URL": RENDER_DB_URL}, allow_render_demo=True
        )


def test_render_opt_in_passes_environment_checks_with_app_env_demo():
    assert_seed_allowed({"APP_ENV": "demo", "RENDER": "true"}, allow_render_demo=True)


def test_cli_refuses_render_without_the_flag(render_demo_env, db, capsys):
    assert run_cli("--expected-database", TEST_DATABASE) == 2
    assert "Refusing to run" in capsys.readouterr().err
    assert db.query(User).count() == 0


def test_cli_refuses_render_flag_without_app_env_demo(render_demo_env, monkeypatch, db, capsys):
    monkeypatch.setenv("APP_ENV", "development")

    assert run_cli("--allow-render-demo", "--expected-database", TEST_DATABASE) == 2
    assert "requires APP_ENV=demo" in capsys.readouterr().err
    assert db.query(User).count() == 0


def test_cli_requires_an_expected_database_name(render_demo_env, db, capsys):
    assert run_cli("--allow-render-demo") == 2
    assert "--expected-database is required" in capsys.readouterr().err
    assert db.query(User).count() == 0


def test_cli_refuses_a_database_name_mismatch(render_demo_env, db, capsys):
    assert run_cli("--allow-render-demo", "--expected-database", "accesshub_demo") == 2

    error = capsys.readouterr().err
    assert f"Connected to database '{TEST_DATABASE}'" in error
    assert "expected 'accesshub_demo'" in error
    assert db.query(User).count() == 0


# =========================================
# Refusal when real accounts exist
# =========================================

def test_cli_refuses_when_non_seed_users_exist(render_demo_env, db, make_user, capsys):
    adminuser = make_user("adminuser", "admin")
    testuser = make_user("testuser", "Admin")
    before = {u.username: (u.role, u.hashed_password, u.is_seed) for u in (adminuser, testuser)}

    assert run_cli("--allow-render-demo", "--expected-database", TEST_DATABASE) == 2
    assert "2 non-seed user record(s)" in capsys.readouterr().err

    db.expire_all()
    users = db.query(User).all()
    assert {u.username: (u.role, u.hashed_password, u.is_seed) for u in users} == before


def test_a_legacy_users_table_counts_every_row_as_real(db):
    # A pre-migration production schema has no is_seed column at all.
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE users"))
        connection.execute(text(
            "CREATE TABLE users (id SERIAL PRIMARY KEY, username VARCHAR,"
            " hashed_password VARCHAR, role VARCHAR)"
        ))
        connection.execute(text(
            "INSERT INTO users (username, hashed_password, role) VALUES ('testuser', 'x', 'Admin')"
        ))

    assert count_non_seed_users(db) == 1
    with pytest.raises(SeedNotAllowed, match="non-seed"):
        verify_demo_database(db, TEST_DATABASE)


def test_demo_admin_never_takes_over_a_real_account(db, make_user):
    real = make_user(DEMO_ADMIN_USERNAME, "member")
    original_hash = real.hashed_password

    with pytest.raises(SeedNotAllowed, match="non-seed account"):
        ensure_demo_admin(db, environ={"APP_ENV": "demo"})

    db.refresh(real)
    assert (real.role, real.is_seed, real.hashed_password) == ("member", False, original_hash)


# =========================================
# Successful opt-in seed
# =========================================

@pytest.mark.parametrize("tables_exist", [True, False])
def test_cli_seeds_an_empty_demo_database(render_demo_env, db, client, capsys, tables_exist):
    if not tables_exist:
        Base.metadata.drop_all(bind=engine)

    assert run_cli("--allow-render-demo", "--expected-database", TEST_DATABASE) == 0
    assert "Created 124 demo users (is_seed=true) and adminDemoUser" in capsys.readouterr().out

    users = db.query(User).all()
    assert len(users) == 125
    assert all(user.is_seed for user in users)

    synthetic = [user for user in users if user.username != DEMO_ADMIN_USERNAME]
    assert len(synthetic) == 124
    assert all(user.username.startswith("demo.") for user in synthetic)
    assert Counter(user.role for user in synthetic) == {
        "admin": 6, "manager": 18, "viewer": 20, "member": 80,
    }
    assert sum(not user.is_active for user in synthetic) == 8

    demo_admin = next(user for user in users if user.username == DEMO_ADMIN_USERNAME)
    assert (demo_admin.role, demo_admin.is_active, demo_admin.must_change_password) == (
        "admin", True, False,
    )

    # Seed accounts, including adminDemoUser, still can't use passwords.
    for username in [DEMO_ADMIN_USERNAME, synthetic[0].username]:
        response = client.post("/login", json={"username": username, "password": PASSWORD})
        assert response.status_code == 401


def test_seeding_the_demo_database_again_changes_nothing(render_demo_env, db, capsys):
    args = ("--allow-render-demo", "--expected-database", TEST_DATABASE)
    assert run_cli(*args) == 0
    assert run_cli(*args) == 0

    assert "Created 0 demo users" in capsys.readouterr().out
    assert db.query(User).count() == 125
