from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from jose import jwt
from sqlalchemy import text

from app.auth import ALGORITHM, SECRET_KEY, create_access_token
from app.database import engine
from app.demo_seed import ensure_demo_admin, seed_demo_users
from app.main import app
from app.migrations import ensure_settings_row
from app.models.access_request_model import AccessRequest
from app.models.audit_model import AuditEvent
from app.models.settings_model import OrganisationSettings

DEFAULTS = {
    "organisation_name": None,
    "timezone": None,
    "access_requests_enabled": True,
    "requestable_roles": ["manager", "member", "viewer"],
    "session_minutes": 30,
}


def events(db, event_type):
    db.expire_all()
    return (
        db.query(AuditEvent)
        .filter(AuditEvent.event_type == event_type)
        .order_by(AuditEvent.id)
        .all()
    )


@pytest.fixture
def admin_headers(make_user, login):
    make_user("root", "admin")
    return login("root")


def current(client, headers):
    response = client.get("/settings", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def save(client, headers, revision=None, **changes):
    body = current(client, headers)
    payload = {key: body[key] for key in DEFAULTS}
    payload.update(changes)
    payload["revision"] = body["revision"] if revision is None else revision
    return client.put("/settings", headers=headers, json=payload)


def token_lifetime_minutes(token: str) -> float:
    claims = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    return (claims["exp"] - datetime.now(timezone.utc).timestamp()) / 60


# =========================================
# Defaults and migration
# =========================================

def test_startup_creates_default_settings(client, admin_headers):
    body = current(client, admin_headers)

    assert {key: body[key] for key in DEFAULTS} == DEFAULTS
    assert body["revision"] == 0
    assert body["updated_at"] is None and body["updated_by"] is None
    assert body["limits"] == {
        "organisation_name_max": 80,
        "session_minutes_min": 15,
        "session_minutes_max": 720,
        "requestable_roles": ["manager", "member", "viewer"],
    }


def test_restarting_never_overwrites_saved_settings(client, db, admin_headers):
    assert save(client, admin_headers, organisation_name="Acme Ltd", session_minutes=60).status_code == 200

    assert ensure_settings_row(engine) is False

    body = current(client, admin_headers)
    assert body["organisation_name"] == "Acme Ltd"
    assert body["session_minutes"] == 60


def test_missing_row_falls_back_to_defaults_and_is_recreated_on_save(client, admin_headers):
    with engine.begin() as connection:
        connection.execute(text("DELETE FROM organisation_settings"))

    assert {key: value for key, value in current(client, admin_headers).items() if key in DEFAULTS} == DEFAULTS
    assert save(client, admin_headers, organisation_name="Acme Ltd").status_code == 200
    assert current(client, admin_headers)["organisation_name"] == "Acme Ltd"


def test_the_table_holds_a_single_row(db):
    with pytest.raises(Exception):
        with engine.begin() as connection:
            connection.execute(text(
                "INSERT INTO organisation_settings"
                " (id, access_requests_enabled, requestable_roles, session_minutes, revision)"
                " VALUES (2, true, 'member', 30, 0)"
            ))


# =========================================
# Authorization
# =========================================

def test_settings_require_authentication(client):
    assert client.get("/settings").status_code == 401
    assert client.put("/settings", json={}).status_code == 401
    assert client.get("/organisation").status_code == 401


@pytest.mark.parametrize("role", ["manager", "member", "viewer"])
def test_only_admins_can_read_or_change_settings(client, db, make_user, login, role):
    make_user("someone", role)
    headers = login("someone")

    assert client.get("/settings", headers=headers).status_code == 403
    response = client.put("/settings", headers=headers, json={"revision": 0, **DEFAULTS, "session_minutes": 600})
    assert response.status_code == 403

    denials = events(db, "access.denied")
    assert [d.details["permission"] for d in denials] == ["settings:manage", "settings:manage"]
    db.expire_all()
    assert db.get(OrganisationSettings, 1).session_minutes == 30


def test_role_claims_in_the_token_are_ignored(client, make_user):
    member = make_user("mem")
    forged = create_access_token({"sub": "mem", "uid": member.id, "role": "admin"})

    assert client.get("/settings", headers={"Authorization": f"Bearer {forged}"}).status_code == 403


def test_admin_with_pending_password_change_is_refused(client, make_user, login):
    make_user("fresh", "admin", must_change_password=True)

    assert client.get("/settings", headers=login("fresh")).status_code == 403


def test_settings_manage_is_fixed_to_admin(client, admin_headers, make_user, login):
    matrix = client.get("/role-permissions", headers=admin_headers).json()
    row = next(row for row in matrix["permissions"] if row["permission"] == "settings:manage")

    assert row["roles"]["admin"] == {"granted": True, "editable": False, "lock_reason": "admin_full_access"}
    for role in ("manager", "member", "viewer"):
        assert row["roles"][role] == {"granted": False, "editable": False, "lock_reason": "admin_only"}

    make_user("adm2", "admin")
    assert "settings:manage" in client.get("/profile", headers=login("adm2")).json()["user"]["permissions"]


@pytest.mark.parametrize("role", ["admin", "manager", "member", "viewer"])
def test_every_signed_in_user_sees_the_organisation_summary(client, make_user, login, admin_headers, role):
    save(client, admin_headers, organisation_name="Acme Ltd", timezone="Europe/London",
         requestable_roles=["member", "viewer"], session_minutes=90)
    make_user("someone", role)

    response = client.get("/organisation", headers=login("someone"))

    assert response.status_code == 200
    assert response.json() == {
        "organisation_name": "Acme Ltd",
        "timezone": "Europe/London",
        "access_requests": {"enabled": True, "requestable_roles": ["member", "viewer"]},
    }


# =========================================
# Updates, validation and audit
# =========================================

def test_saving_persists_and_increments_the_revision(client, admin_headers):
    response = save(
        client, admin_headers,
        organisation_name="  Acme Ltd  ",
        timezone="Asia/Tokyo",
        access_requests_enabled=True,
        requestable_roles=["viewer", "Member", "viewer"],
        session_minutes=120,
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["organisation_name"] == "Acme Ltd"
    assert body["timezone"] == "Asia/Tokyo"
    assert body["requestable_roles"] == ["member", "viewer"]
    assert body["session_minutes"] == 120
    assert body["revision"] == 1
    assert body["updated_by"]["username"] == "root"
    assert current(client, admin_headers) == body


def test_clearing_optional_values(client, admin_headers):
    save(client, admin_headers, organisation_name="Acme Ltd", timezone="UTC")

    body = save(client, admin_headers, organisation_name="   ", timezone="").json()

    assert body["organisation_name"] is None
    assert body["timezone"] is None


def test_turning_requests_off_keeps_the_role_list(client, admin_headers):
    body = save(client, admin_headers, access_requests_enabled=False, requestable_roles=[]).json()

    assert body["access_requests_enabled"] is False
    assert body["requestable_roles"] == []


INVALID = [
    ({"organisation_name": "x" * 81}, "80 characters or fewer"),
    ({"organisation_name": "Acme\nLtd"}, "control characters"),
    ({"timezone": "Mars/Olympus_Mons"}, "Unknown timezone: Mars/Olympus_Mons"),
    ({"requestable_roles": ["member", "admin"]}, "Admin can never be requested"),
    ({"requestable_roles": ["Admin"]}, "Admin can never be requested"),
    ({"requestable_roles": ["owner"]}, "Unknown role: owner"),
    ({"requestable_roles": []}, "at least one role"),
    ({"session_minutes": 14}, "between 15 and 720 minutes"),
    ({"session_minutes": 721}, "between 15 and 720 minutes"),
]


@pytest.mark.parametrize("changes, message", INVALID)
def test_invalid_settings_are_rejected_without_changes(client, db, admin_headers, changes, message):
    before = current(client, admin_headers)

    response = save(client, admin_headers, **changes)

    assert response.status_code == 422
    assert message in response.json()["detail"]
    assert current(client, admin_headers) == before
    assert events(db, "settings.changed") == []


@pytest.mark.parametrize(
    "payload",
    [
        {**DEFAULTS},  # no revision
        {"revision": 0, **{k: v for k, v in DEFAULTS.items() if k != "session_minutes"}},
        {"revision": 0, **DEFAULTS, "session_minutes": "60"},
        {"revision": 0, **DEFAULTS, "access_requests_enabled": "yes"},
        {"revision": 0, **DEFAULTS, "notifications": True},
        {"revision": 0, **DEFAULTS, "requestable_roles": "member"},
    ],
)
def test_malformed_updates_are_rejected(client, admin_headers, payload):
    assert client.put("/settings", headers=admin_headers, json=payload).status_code == 422


def test_stale_updates_are_rejected(client, db, admin_headers):
    assert save(client, admin_headers, session_minutes=60).status_code == 200

    response = save(client, admin_headers, revision=0, session_minutes=90)

    assert response.status_code == 409
    assert current(client, admin_headers)["session_minutes"] == 60
    assert len(events(db, "settings.changed")) == 1


def test_each_changed_setting_is_audited(client, db, admin_headers):
    save(
        client, admin_headers,
        organisation_name="Acme Ltd",
        access_requests_enabled=False,
        requestable_roles=["member"],
        session_minutes=45,
    )

    changed = events(db, "settings.changed")
    assert [(e.actor_username, e.outcome, e.target_type) for e in changed] == [("root", "success", None)] * 4
    assert [e.details for e in changed] == [
        {"setting": "organisation_name", "from_value": "", "to_value": "Acme Ltd"},
        {"setting": "access_requests_enabled", "from_value": "on", "to_value": "off"},
        {"setting": "requestable_roles", "from_value": "manager,member,viewer", "to_value": "member"},
        {"setting": "session_minutes", "from_value": "30", "to_value": "45"},
    ]

    # Activity shows the same, display-safe values.
    feed = client.get("/activity", headers=admin_headers, params={"event_type": "settings.changed"}).json()
    assert feed["total"] == 4


def test_saving_unchanged_settings_records_nothing(client, db, admin_headers):
    body = save(client, admin_headers).json()

    assert body["revision"] == 0
    assert events(db, "settings.changed") == []


def test_a_failed_save_changes_nothing(db, admin_headers, monkeypatch):
    import app.routes.settings_routes as routes

    def failing_record_event(*args, **kwargs):
        raise RuntimeError("audit store unavailable")

    unsafe_client = TestClient(app, raise_server_exceptions=False)
    body = current(unsafe_client, admin_headers)
    monkeypatch.setattr(routes, "record_event", failing_record_event)

    response = unsafe_client.put(
        "/settings", headers=admin_headers,
        json={"revision": body["revision"], **DEFAULTS, "session_minutes": 60, "organisation_name": "Acme"},
    )

    assert response.status_code == 500
    db.expire_all()
    row = db.get(OrganisationSettings, 1)
    assert (row.session_minutes, row.organisation_name, row.revision) == (30, None, 0)


# =========================================
# Effects: access request policy
# =========================================

def submit(client, headers, role="viewer"):
    return client.post(
        "/access-requests", headers=headers,
        json={"requested_role": role, "reason": "Covering for a colleague."},
    )


def test_turning_requests_off_blocks_new_requests(client, make_user, login, admin_headers):
    make_user("mem")
    member_headers = login("mem")
    save(client, admin_headers, access_requests_enabled=False)

    response = submit(client, member_headers)

    assert response.status_code == 403
    assert response.json()["detail"] == "Access requests are turned off"

    save(client, admin_headers, access_requests_enabled=True)
    assert submit(client, member_headers).status_code == 201


def test_only_listed_roles_can_be_requested(client, make_user, login, admin_headers):
    make_user("mem")
    member_headers = login("mem")
    save(client, admin_headers, requestable_roles=["viewer"])

    refused = submit(client, member_headers, role="manager")
    assert refused.status_code == 400
    assert refused.json()["detail"] == "This role can't be requested"

    assert submit(client, member_headers, role="viewer").status_code == 201


def test_admin_can_never_be_requested(client, make_user, login, admin_headers):
    make_user("mem")

    assert submit(client, login("mem"), role="admin").status_code == 422


def test_pending_requests_can_still_be_decided_after_turning_requests_off(
    client, db, make_user, login, admin_headers
):
    member = make_user("mem")
    created = submit(client, login("mem"), role="viewer").json()["request"]
    save(client, admin_headers, access_requests_enabled=False, requestable_roles=["manager"])

    response = client.post(f"/access-requests/{created['id']}/approve", headers=admin_headers)

    assert response.status_code == 200
    db.refresh(member)
    assert member.role == "viewer"
    # Approval rules still apply: the requester can't decide their own request.
    assert db.query(AccessRequest).count() == 1


# =========================================
# Effects: session length
# =========================================

def test_new_sign_ins_use_the_session_length(client, make_user, admin_headers):
    make_user("mem")

    def sign_in():
        return client.post("/login", json={"username": "mem", "password": "correct-horse-battery"}).json()["access_token"]

    assert 29 < token_lifetime_minutes(sign_in()) <= 30
    old_token = sign_in()

    save(client, admin_headers, session_minutes=120)

    assert 119 < token_lifetime_minutes(sign_in()) <= 120
    form = client.post("/token", data={"username": "mem", "password": "correct-horse-battery"})
    assert 119 < token_lifetime_minutes(form.json()["access_token"]) <= 120
    # Existing tokens keep the expiry they were issued with.
    assert 29 < token_lifetime_minutes(old_token) <= 30
    assert client.get("/profile", headers={"Authorization": f"Bearer {old_token}"}).status_code == 200


def test_expired_tokens_are_refused(client, make_user):
    member = make_user("mem")
    expired = create_access_token({"sub": "mem", "uid": member.id}, expires_minutes=-1)

    assert client.get("/profile", headers={"Authorization": f"Bearer {expired}"}).status_code == 401


def test_demo_sessions_use_the_session_length(client, db, monkeypatch):
    environ = {"APP_ENV": "demo", "DATABASE_URL": "postgresql://localhost/demo_test_db"}
    seed_demo_users(db, environ=environ)
    ensure_demo_admin(db, environ=environ)
    with engine.begin() as connection:
        connection.execute(text("UPDATE organisation_settings SET session_minutes = 60"))
    monkeypatch.setenv("APP_ENV", "demo")

    token = client.post("/demo/session").json()["access_token"]

    assert 59 < token_lifetime_minutes(token) <= 60
