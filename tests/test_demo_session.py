from app.demo_seed import DEMO_ADMIN_USERNAME, ensure_demo_admin, seed_demo_users
from app.models.user_model import User
from tests.conftest import PASSWORD


DEMO_ENV = {"APP_ENV": "demo", "DATABASE_URL": "postgresql://localhost/demo_test_db"}


def seed_demo(db):
    seed_demo_users(db, environ=DEMO_ENV)
    ensure_demo_admin(db, environ=DEMO_ENV)


def test_demo_session_does_not_exist_outside_demo_mode(client, db, monkeypatch):
    seed_demo(db)

    for app_env in ["production", "development", "test", ""]:
        monkeypatch.setenv("APP_ENV", app_env)
        assert client.post("/demo/session").status_code == 404


def test_demo_session_signs_in_admin_demo_user_and_shows_synthetic_users(client, db, monkeypatch):
    seed_demo(db)
    monkeypatch.setenv("APP_ENV", "demo")

    response = client.post("/demo/session")

    assert response.status_code == 200
    headers = {"Authorization": f"Bearer {response.json()['access_token']}"}
    assert client.get("/profile", headers=headers).json()["user"]["username"] == DEMO_ADMIN_USERNAME

    users = client.get("/users", headers=headers).json()["users"]
    assert len(users) == 125  # 124 synthetic users + adminDemoUser
    assert all(user["is_seed"] for user in users)


def test_demo_session_refuses_when_any_real_account_exists(client, db, make_user, monkeypatch):
    seed_demo(db)
    make_user("real.admin", "admin")
    monkeypatch.setenv("APP_ENV", "demo")

    response = client.post("/demo/session")

    assert response.status_code == 503
    assert "non-demo accounts" in response.json()["detail"]


def test_demo_session_requires_a_seeded_demo_admin(client, monkeypatch):
    monkeypatch.setenv("APP_ENV", "demo")

    assert client.post("/demo/session").status_code == 503


def test_demo_admin_and_seed_accounts_still_cannot_sign_in_with_a_password(client, db, monkeypatch):
    seed_demo(db)
    monkeypatch.setenv("APP_ENV", "demo")
    demo_admin = db.query(User).filter(User.username == DEMO_ADMIN_USERNAME).one()

    assert demo_admin.is_seed is True
    assert demo_admin.role == "admin"
    for username in [DEMO_ADMIN_USERNAME, "demo.alex.carter"]:
        response = client.post("/login", json={"username": username, "password": PASSWORD})
        assert response.status_code == 401


def test_users_created_during_a_demo_are_demo_data(client, db, monkeypatch):
    seed_demo(db)
    monkeypatch.setenv("APP_ENV", "demo")
    token = client.post("/demo/session").json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    created = client.post("/users", headers=headers, json={"username": "visitor.made", "role": "member"})

    assert created.status_code == 200
    assert created.json()["user"]["is_seed"] is True
    # The guard still holds: no real accounts were introduced.
    assert client.post("/demo/session").status_code == 200


def test_users_created_outside_demo_mode_are_real(client, make_user, login):
    make_user("admin1", "admin")

    created = client.post(
        "/users", headers=login("admin1"), json={"username": "real.hire", "role": "member"}
    )

    assert created.json()["user"]["is_seed"] is False


def test_demo_admin_is_created_once(db):
    assert ensure_demo_admin(db, environ=DEMO_ENV) is True
    assert ensure_demo_admin(db, environ=DEMO_ENV) is False
