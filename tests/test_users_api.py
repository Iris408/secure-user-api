import logging

import pytest
from fastapi import HTTPException

from app.auth import create_access_token
from app.routes.user_routes import ensure_another_active_admin
from tests.conftest import PASSWORD


# =========================================
# Authentication and backwards compatibility
# =========================================

def test_login_response_shape_is_unchanged(client, make_user):
    make_user("member1")

    response = client.post("/login", json={"username": "member1", "password": PASSWORD})

    assert response.status_code == 200
    assert set(response.json()) == {"access_token", "token_type"}
    assert response.json()["token_type"] == "bearer"


def test_login_rejects_wrong_password(client, make_user):
    make_user("member1")

    response = client.post("/login", json={"username": "member1", "password": "nope-nope-nope"})

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password"


def test_profile_returns_role_and_permissions(client, make_user, login):
    make_user("member1", "member")

    response = client.get("/profile", headers=login("member1"))

    assert response.status_code == 200
    user = response.json()["user"]
    assert user["role"] == "member"
    assert user["permissions"] == ["access_requests:submit"]
    assert user["is_active"] is True


def test_legacy_role_values_keep_their_access(client, make_user, login):
    make_user("legacy-admin", "Admin")
    make_user("legacy-user", "user")

    admin_headers = login("legacy-admin")
    assert client.get("/profile", headers=admin_headers).json()["user"]["role"] == "admin"

    listing = client.get("/users", headers=admin_headers)
    assert listing.status_code == 200
    roles = {user["username"]: user["role"] for user in listing.json()["users"]}
    assert roles == {"legacy-admin": "admin", "legacy-user": "member"}

    member_headers = login("legacy-user")
    assert client.get("/users", headers=member_headers).status_code == 403


def test_users_list_keeps_its_response_shape(client, make_user, login):
    make_user("admin1", "admin")

    body = client.get("/users", headers=login("admin1")).json()

    assert list(body) == ["users"]
    assert {"id", "username", "role"} <= set(body["users"][0])


def test_tokens_issued_before_uid_still_work(client, make_user):
    make_user("admin1", "admin")
    legacy_token = create_access_token({"sub": "admin1", "role": "admin"})

    response = client.get("/users", headers={"Authorization": f"Bearer {legacy_token}"})

    assert response.status_code == 200


def test_role_claim_in_token_is_not_trusted(client, make_user):
    member = make_user("member1", "member")
    # A token claiming admin (e.g. issued before a demotion) gets no admin access.
    token = create_access_token({"sub": "member1", "uid": member.id, "role": "admin"})

    response = client.get("/users", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 403


def test_invalid_token_is_rejected(client):
    response = client.get("/profile", headers={"Authorization": "Bearer not-a-token"})

    assert response.status_code == 401


# =========================================
# Authorization boundaries
# =========================================

PROTECTED_ROUTES = [
    ("get", "/users", None),
    ("post", "/users", {"username": "someone", "role": "member"}),
    ("get", "/users/1", None),
    ("put", "/users/1", {"username": "someone", "role": "member"}),
    ("post", "/users/1/deactivate", None),
    ("post", "/users/1/reactivate", None),
    ("delete", "/users/1", None),
    ("post", "/profile/password", {"current_password": "x", "new_password": "y" * 12}),
]


@pytest.mark.parametrize("method, path, body", PROTECTED_ROUTES)
def test_user_routes_require_authentication(client, method, path, body):
    response = client.request(method, path, json=body)

    assert response.status_code == 401


@pytest.mark.parametrize("role", ["manager", "member", "viewer"])
def test_only_admins_can_manage_users(client, make_user, login, role):
    make_user("actor", role)
    target = make_user("target", "member")
    headers = login("actor")

    attempts = [
        client.get("/users", headers=headers),
        client.post("/users", headers=headers, json={"username": "new-user", "role": "admin"}),
        client.get(f"/users/{target.id}", headers=headers),
        client.put(f"/users/{target.id}", headers=headers, json={"username": "renamed", "role": "admin"}),
        client.post(f"/users/{target.id}/deactivate", headers=headers),
        client.post(f"/users/{target.id}/reactivate", headers=headers),
        client.delete(f"/users/{target.id}", headers=headers),
    ]

    assert [response.status_code for response in attempts] == [403] * len(attempts)


def test_users_can_read_their_own_record(client, make_user, login):
    member = make_user("member1")

    response = client.get(f"/users/{member.id}", headers=login("member1"))

    assert response.status_code == 200
    assert response.json()["user"]["username"] == "member1"


def test_self_registration_cannot_create_admins(client):
    # POST /users used to be open to anyone, with any role.
    response = client.post(
        "/users",
        json={"username": "intruder", "password": "x" * 16, "role": "admin"},
    )

    assert response.status_code == 401


# =========================================
# Create users and temporary passwords
# =========================================

def test_admin_creates_user_with_one_time_temporary_password(client, make_user, login, caplog):
    make_user("admin1", "admin")
    caplog.set_level(logging.DEBUG)

    response = client.post(
        "/users",
        headers=login("admin1"),
        json={"username": "new.hire", "role": "manager"},
    )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    temporary_password = body["temporary_password"]
    assert len(temporary_password) >= 20
    assert body["user"] == {
        "id": body["user"]["id"],
        "username": "new.hire",
        "role": "manager",
        "is_active": True,
        "is_seed": False,
        "must_change_password": True,
    }
    assert temporary_password not in caplog.text

    # The new user can sign in, but must change the password before doing
    # anything else.
    new_headers = login("new.hire", temporary_password)
    profile = client.get("/profile", headers=new_headers)
    assert profile.status_code == 200
    assert profile.json()["user"]["must_change_password"] is True

    blocked = client.get(f"/users/{body['user']['id']}", headers=new_headers)
    assert blocked.status_code == 403
    assert blocked.json()["detail"] == "Password change required"


def test_admin_supplied_password_is_temporary_and_not_echoed(client, make_user, login):
    make_user("admin1", "admin")

    response = client.post(
        "/users",
        headers=login("admin1"),
        json={"username": "new.hire", "password": "a-strong-temp-pass", "role": "member"},
    )

    assert response.status_code == 200
    assert "temporary_password" not in response.json()
    assert response.json()["user"]["must_change_password"] is True


@pytest.mark.parametrize(
    "payload, status",
    [
        ({"username": "ok.name", "role": "user"}, 200),  # legacy alias → member
        ({"username": "ok.name", "role": "superuser"}, 422),
        ({"username": "x", "role": "member"}, 422),
        ({"username": "bad name!", "role": "member"}, 422),
        ({"username": "ok.name", "password": "short", "role": "member"}, 422),
    ],
)
def test_create_user_validation(client, make_user, login, payload, status):
    make_user("admin1", "admin")

    response = client.post("/users", headers=login("admin1"), json=payload)

    assert response.status_code == status
    if status == 200:
        assert response.json()["user"]["role"] == "member"


def test_create_user_rejects_duplicate_username(client, make_user, login):
    make_user("admin1", "admin")
    make_user("taken")

    response = client.post(
        "/users", headers=login("admin1"), json={"username": "taken", "role": "member"}
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Username already exists"


# =========================================
# Change password
# =========================================

def test_change_password_clears_the_requirement(client, make_user, login):
    make_user("new.hire", must_change_password=True)
    headers = login("new.hire")

    wrong = client.post(
        "/profile/password",
        headers=headers,
        json={"current_password": "wrong-password", "new_password": "a-brand-new-password"},
    )
    assert wrong.status_code == 400
    # A wrong current password must not end the session.
    assert client.get("/profile", headers=headers).status_code == 200

    same = client.post(
        "/profile/password",
        headers=headers,
        json={"current_password": PASSWORD, "new_password": PASSWORD},
    )
    assert same.status_code == 400

    changed = client.post(
        "/profile/password",
        headers=headers,
        json={"current_password": PASSWORD, "new_password": "a-brand-new-password"},
    )
    assert changed.status_code == 200
    assert client.get("/profile", headers=headers).json()["user"]["must_change_password"] is False

    assert client.post("/login", json={"username": "new.hire", "password": PASSWORD}).status_code == 401
    login("new.hire", "a-brand-new-password")


def test_change_password_enforces_policy(client, make_user, login):
    make_user("member1")

    response = client.post(
        "/profile/password",
        headers=login("member1"),
        json={"current_password": PASSWORD, "new_password": "short"},
    )

    assert response.status_code == 422


# =========================================
# Update users
# =========================================

def test_role_change_applies_immediately(client, make_user, login):
    make_user("admin1", "admin")
    member = make_user("member1", "member")
    member_headers = login("member1")

    response = client.put(
        f"/users/{member.id}",
        headers=login("admin1"),
        json={"username": "member1", "role": "viewer"},
    )

    assert response.status_code == 200
    assert response.json()["user"]["role"] == "viewer"
    # Existing token, new permissions.
    permissions = client.get("/profile", headers=member_headers).json()["user"]["permissions"]
    assert permissions == ["activity:read_all", "audit:read"]


def test_admins_cannot_change_their_own_role(client, make_user, login):
    admin = make_user("admin1", "admin")
    make_user("admin2", "admin")

    response = client.put(
        f"/users/{admin.id}",
        headers=login("admin1"),
        json={"username": "admin1", "role": "member"},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "You can't change your own role"


def test_renaming_yourself_keeps_your_session(client, make_user, login):
    admin = make_user("admin1", "admin")
    headers = login("admin1")

    response = client.put(
        f"/users/{admin.id}", headers=headers, json={"username": "admin.one", "role": "admin"}
    )

    assert response.status_code == 200
    assert client.get("/profile", headers=headers).json()["user"]["username"] == "admin.one"


def test_update_rejects_taken_username(client, make_user, login):
    make_user("admin1", "admin")
    member = make_user("member1")
    make_user("member2")

    response = client.put(
        f"/users/{member.id}",
        headers=login("admin1"),
        json={"username": "member2", "role": "member"},
    )

    assert response.status_code == 400


def test_update_unknown_user_returns_404(client, make_user, login):
    make_user("admin1", "admin")

    response = client.put(
        "/users/9999", headers=login("admin1"), json={"username": "ghost", "role": "member"}
    )

    assert response.status_code == 404


# =========================================
# Deactivate, reactivate and delete
# =========================================

def test_deactivation_ends_access_and_reactivation_restores_it(client, make_user, login):
    make_user("admin1", "admin")
    member = make_user("member1")
    admin_headers = login("admin1")
    member_headers = login("member1")

    response = client.post(f"/users/{member.id}/deactivate", headers=admin_headers)
    assert response.status_code == 200
    assert response.json()["user"]["is_active"] is False

    # Existing session ends immediately; signing in again is refused.
    assert client.get("/profile", headers=member_headers).status_code == 401
    relogin = client.post("/login", json={"username": "member1", "password": PASSWORD})
    assert relogin.status_code == 403
    assert relogin.json()["detail"] == "Account is deactivated"

    listing = client.get("/users", headers=admin_headers).json()["users"]
    assert {u["username"]: u["is_active"] for u in listing}["member1"] is False

    assert client.post(f"/users/{member.id}/reactivate", headers=admin_headers).status_code == 200
    login("member1")


def test_deactivated_status_is_not_revealed_without_the_password(client, make_user):
    make_user("member1", is_active=False)

    response = client.post("/login", json={"username": "member1", "password": "wrong-password"})

    assert response.status_code == 401


def test_admins_cannot_deactivate_or_delete_themselves(client, make_user, login):
    admin = make_user("admin1", "admin")
    headers = login("admin1")

    deactivate = client.post(f"/users/{admin.id}/deactivate", headers=headers)
    delete = client.delete(f"/users/{admin.id}", headers=headers)

    assert deactivate.status_code == 409
    assert deactivate.json()["detail"] == "You can't deactivate your own account"
    assert delete.status_code == 409


def test_permanent_delete_requires_deactivation_first(client, make_user, login):
    make_user("admin1", "admin")
    member = make_user("member1")
    headers = login("admin1")

    active_delete = client.delete(f"/users/{member.id}", headers=headers)
    assert active_delete.status_code == 409
    assert active_delete.json()["detail"] == "Deactivate the user before deleting them permanently"

    client.post(f"/users/{member.id}/deactivate", headers=headers)
    deleted = client.delete(f"/users/{member.id}", headers=headers)

    assert deleted.status_code == 200
    assert deleted.json()["message"] == "User deleted"
    assert deleted.json()["deleted_user"]["username"] == "member1"
    assert client.get(f"/users/{member.id}", headers=headers).status_code == 404


def test_another_admin_can_be_deactivated_while_one_remains(client, make_user, login):
    make_user("admin1", "admin")
    admin2 = make_user("admin2", "admin")

    response = client.post(f"/users/{admin2.id}/deactivate", headers=login("admin1"))

    assert response.status_code == 200


def test_last_active_admin_guard(db, make_user):
    only_admin = make_user("admin1", "Admin")
    make_user("demo.admin", "admin", is_seed=True)
    make_user("old.admin", "admin", is_active=False)

    # Seed and inactive admins can't sign in, so they don't count.
    with pytest.raises(HTTPException) as error:
        ensure_another_active_admin(db, only_admin, "Cannot deactivate the last active admin")

    assert error.value.status_code == 409

    make_user("admin2", "admin")
    ensure_another_active_admin(db, only_admin, "unused")


def test_seed_accounts_cannot_sign_in(client, make_user):
    make_user("demo.ava.carter", "admin", is_seed=True)

    response = client.post("/login", json={"username": "demo.ava.carter", "password": PASSWORD})

    assert response.status_code == 401
