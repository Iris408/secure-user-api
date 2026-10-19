from collections import Counter

import pytest

from app.demo_seed import (
    SEED_COUNT,
    SeedNotAllowed,
    assert_seed_allowed,
    remove_demo_users,
    seed_demo_users,
)
from app.models.user_model import User
from scripts import seed_demo_users as seed_cli


TEST_ENV = {"APP_ENV": "test", "DATABASE_URL": "postgresql://localhost/test_db"}


@pytest.mark.parametrize(
    "environ",
    [
        {},
        {"APP_ENV": "production"},
        {"APP_ENV": "staging"},
        {"APP_ENV": "development", "RENDER": "true"},
        {
            "APP_ENV": "development",
            "DATABASE_URL": "postgresql://u:p@dpg-abc.oregon-postgres.render.com/db",
        },
    ],
)
def test_seeding_is_refused_outside_demo_environments(environ):
    with pytest.raises(SeedNotAllowed):
        assert_seed_allowed(environ)


def test_refusal_happens_before_touching_the_database(db, make_user):
    make_user("real.user")

    with pytest.raises(SeedNotAllowed):
        seed_demo_users(db, environ={"APP_ENV": "production"})
    with pytest.raises(SeedNotAllowed):
        remove_demo_users(db, environ={"APP_ENV": "production"})

    assert db.query(User).count() == 1


def test_seeds_124_clearly_marked_demo_users(db):
    created = seed_demo_users(db, environ=TEST_ENV)

    users = db.query(User).all()
    assert created == SEED_COUNT == len(users) == 124
    assert all(user.is_seed for user in users)
    assert all(user.username.startswith("demo.") for user in users)
    assert len({user.username for user in users}) == 124

    roles = Counter(user.role for user in users)
    assert roles == {"admin": 6, "manager": 18, "viewer": 20, "member": 80}
    assert sum(not user.is_active for user in users) == 8


def test_seeding_is_idempotent(db):
    seed_demo_users(db, environ=TEST_ENV)

    assert seed_demo_users(db, environ=TEST_ENV) == 0
    assert db.query(User).count() == 124


def test_removal_only_deletes_seed_users(db, make_user):
    make_user("real.admin", "admin")
    seed_demo_users(db, environ=TEST_ENV)

    removed = remove_demo_users(db, environ=TEST_ENV)

    assert removed == 124
    assert [user.username for user in db.query(User).all()] == ["real.admin"]


def test_seeded_admins_cannot_sign_in(client, db):
    seed_demo_users(db, environ=TEST_ENV)
    seed_admin = db.query(User).filter(User.role == "admin").first()

    response = client.post(
        "/login", json={"username": seed_admin.username, "password": "anything-at-all"}
    )

    assert response.status_code == 401


def test_cli_refuses_in_production(monkeypatch, capsys):
    monkeypatch.setenv("APP_ENV", "production")

    assert seed_cli.main([]) == 2
    assert "Refusing to run" in capsys.readouterr().err
