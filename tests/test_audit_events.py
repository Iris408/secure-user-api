import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import exc, text

from app.audit import AuditEventType, AuditOutcome, record_event, safe_details
from app.auth import create_access_token
from app.database import engine
from app.demo_seed import ensure_demo_admin, seed_demo_users
from app.models.audit_model import AuditEvent
from tests.conftest import PASSWORD


def events(db, event_type=None):
    db.expire_all()
    query = db.query(AuditEvent).order_by(AuditEvent.id)
    if event_type:
        query = query.filter(AuditEvent.event_type == event_type)
    return query.all()


def everything_stored(db) -> str:
    """Every audit column of every row, for searching for leaked secrets."""
    with engine.connect() as connection:
        rows = connection.execute(text("SELECT * FROM audit_events")).mappings().all()
    return json.dumps([dict(row) for row in rows], default=str)


# =========================================
# Sign-in events
# =========================================

def test_successful_sign_in_is_recorded(client, db, make_user, login):
    user = make_user("member1")

    login("member1")
    client.post("/token", data={"username": "member1", "password": PASSWORD})

    recorded = events(db, "auth.sign_in")
    assert [(e.outcome, e.details["method"]) for e in recorded] == [
        ("success", "password"),
        ("success", "oauth2_form"),
    ]
    assert recorded[0].actor_id == recorded[0].target_id == user.id
    assert recorded[0].actor_username == "member1"
    assert recorded[0].actor_role == "member"


def test_failed_sign_in_records_the_account_but_never_the_password(client, db, make_user):
    user = make_user("member1")

    client.post("/login", json={"username": "member1", "password": "Wrong-Guess-123"})

    [event] = events(db, "auth.sign_in")
    assert (event.outcome, event.details["reason"]) == ("failure", "invalid_credentials")
    assert event.actor_id is None
    assert event.target_id == user.id
    assert "Wrong-Guess-123" not in everything_stored(db)


def test_failed_sign_in_for_an_unknown_account_does_not_store_the_typed_text(client, db):
    # People sometimes type their password into the username field.
    client.post("/login", json={"username": "MyPassw0rd!!", "password": "anything"})

    [event] = events(db, "auth.sign_in")
    assert event.outcome == "failure"
    assert event.actor_id is None and event.target_id is None
    assert "MyPassw0rd" not in everything_stored(db)


def test_deactivated_and_seed_sign_ins_are_recorded_as_failures(client, db, make_user):
    make_user("old.member", is_active=False)
    make_user("demo.ava.carter", is_seed=True)

    client.post("/login", json={"username": "old.member", "password": PASSWORD})
    client.post("/login", json={"username": "demo.ava.carter", "password": PASSWORD})

    reasons = [(e.target_username, e.outcome, e.details["reason"]) for e in events(db)]
    assert reasons == [
        ("old.member", "failure", "account_deactivated"),
        ("demo.ava.carter", "failure", "invalid_credentials"),
    ]


# =========================================
# Password changes
# =========================================

def test_password_changes_are_recorded_without_passwords(client, db, make_user, login):
    make_user("member1", must_change_password=True)
    headers = login("member1")

    client.post("/profile/password", headers=headers,
                json={"current_password": "Not-The-Password-1", "new_password": "A-New-Password-2026"})
    client.post("/profile/password", headers=headers,
                json={"current_password": PASSWORD, "new_password": PASSWORD})
    client.post("/profile/password", headers=headers,
                json={"current_password": PASSWORD, "new_password": "A-New-Password-2026"})

    recorded = events(db, "auth.password_changed")
    assert [(e.outcome, e.details.get("reason")) for e in recorded] == [
        ("failure", "incorrect_current_password"),
        ("failure", "password_unchanged"),
        ("success", None),
    ]

    stored = everything_stored(db)
    for secret in ["Not-The-Password-1", "A-New-Password-2026", PASSWORD]:
        assert secret not in stored


# =========================================
# User administration
# =========================================

def test_user_creation_is_recorded_without_the_temporary_password(client, db, make_user, login):
    admin = make_user("admin1", "admin")
    headers = login("admin1")

    response = client.post("/users", headers=headers, json={"username": "new.hire", "role": "manager"})
    temporary_password = response.json()["temporary_password"]

    [event] = events(db, "user.created")
    assert event.outcome == "success"
    assert (event.actor_id, event.actor_username) == (admin.id, "admin1")
    assert event.target_username == "new.hire"
    assert event.details == {"role": "manager", "password_generated": True}

    stored = everything_stored(db)
    assert temporary_password not in stored
    assert headers["Authorization"].split()[1] not in stored


def test_renames_and_role_changes_are_recorded_separately(client, db, make_user, login):
    make_user("admin1", "admin")
    member = make_user("member1")
    headers = login("admin1")

    client.put(f"/users/{member.id}", headers=headers, json={"username": "member1", "role": "member"})
    client.put(f"/users/{member.id}", headers=headers, json={"username": "member.one", "role": "viewer"})

    recorded = [(e.event_type, e.details) for e in events(db) if e.event_type.startswith("user.")]
    assert recorded == [
        ("user.updated", {"from_username": "member1", "to_username": "member.one"}),
        ("user.role_changed", {"from_role": "member", "to_role": "viewer"}),
    ]


def test_lifecycle_events_keep_a_snapshot_after_deletion(client, db, make_user, login):
    make_user("admin1", "admin")
    member_id = make_user("member1", "manager").id
    headers = login("admin1")

    client.post(f"/users/{member_id}/deactivate", headers=headers)
    client.post(f"/users/{member_id}/reactivate", headers=headers)
    client.post(f"/users/{member_id}/deactivate", headers=headers)
    assert client.delete(f"/users/{member_id}", headers=headers).status_code == 200

    recorded = [(e.event_type, e.outcome, e.target_id, e.target_username)
                for e in events(db) if e.event_type.startswith("user.")]
    assert recorded == [
        ("user.deactivated", "success", member_id, "member1"),
        ("user.reactivated", "success", member_id, "member1"),
        ("user.deactivated", "success", member_id, "member1"),
        ("user.deleted", "success", member_id, "member1"),
    ]
    assert events(db, "user.deleted")[0].details == {"role": "manager"}


def test_refused_safeguards_are_recorded_as_denied(client, db, make_user, login):
    admin = make_user("admin1", "admin")
    member = make_user("member1")
    headers = login("admin1")

    assert client.post(f"/users/{admin.id}/deactivate", headers=headers).status_code == 409
    assert client.delete(f"/users/{member.id}", headers=headers).status_code == 409
    assert client.put(f"/users/{admin.id}", headers=headers,
                      json={"username": "admin1", "role": "member"}).status_code == 409

    recorded = [(e.event_type, e.outcome, e.details["reason"]) for e in events(db)
                if e.event_type.startswith("user.")]
    assert recorded == [
        ("user.deactivated", "denied", "own_account"),
        ("user.deleted", "denied", "still_active"),
        ("user.role_changed", "denied", "own_role"),
    ]


def test_permission_denials_are_recorded_with_the_route_template(client, db, make_user, login):
    make_user("admin1", "admin")
    target = make_user("target")
    member = make_user("member1")
    headers = login("member1")

    client.get("/users", headers=headers)
    client.post(f"/users/{target.id}/deactivate", headers=headers)

    recorded = [(e.actor_id, e.details) for e in events(db, "access.denied")]
    assert recorded == [
        (member.id, {"permission": "users:read", "action": "GET /users", "reason": "missing_permission"}),
        (member.id, {"permission": "users:manage", "action": "POST /users/{user_id}/deactivate",
                     "reason": "missing_permission"}),
    ]


def test_routine_reads_are_not_recorded(client, db, make_user, login):
    make_user("admin1", "admin")
    headers = login("admin1")
    before = len(events(db))

    client.get("/profile", headers=headers)
    client.get("/users", headers=headers)
    client.get("/audit-events", headers=headers)

    assert len(events(db)) == before


def test_demo_sessions_are_recorded(client, db, make_user, monkeypatch):
    demo_env = {"APP_ENV": "demo", "DATABASE_URL": "postgresql://localhost/demo_test_db"}
    seed_demo_users(db, environ=demo_env)
    ensure_demo_admin(db, environ=demo_env)
    monkeypatch.setenv("APP_ENV", "demo")

    token = client.post("/demo/session").json()["access_token"]
    make_user("real.person")
    client.post("/demo/session")

    recorded = [(e.outcome, e.actor_username, e.details) for e in events(db, "auth.demo_session")]
    assert recorded == [
        ("success", "adminDemoUser", {"method": "demo_session"}),
        ("denied", None, {"reason": "real_accounts_present"}),
    ]
    assert token not in everything_stored(db)


# =========================================
# Redaction
# =========================================

def test_safe_details_keeps_only_allow_listed_simple_values():
    cleaned = safe_details({
        "reason": "x" * 500,
        "role": "admin",
        "password_generated": True,
        "password": "hunter2",
        "temporary_password": "abc",
        "token": "eyJhbGciOi",
        "secret_key": "s",
        "nested": {"password": "hunter2"},
        "permission": ["users:read"],
    })

    assert cleaned == {"reason": "x" * 200, "role": "admin", "password_generated": True}


def test_record_event_cannot_store_credentials(db, make_user):
    user = make_user("member1")

    record_event(db, AuditEventType.USER_UPDATED, AuditOutcome.SUCCESS, actor=user, target=user,
                 details={"password": "hunter2", "access_token": "eyJ.x.y", "reason": "ok"})
    db.commit()

    assert events(db)[-1].details == {"reason": "ok"}
    assert "hunter2" not in everything_stored(db)


# =========================================
# The audit API: authorization
# =========================================

def test_audit_log_requires_authentication(client):
    assert client.get("/audit-events").status_code == 401


@pytest.mark.parametrize("role", ["manager", "member", "viewer"])
def test_audit_log_is_admin_only(client, db, make_user, login, role):
    user = make_user("someone", role)

    response = client.get("/audit-events", headers=login("someone"))

    assert response.status_code == 403
    denial = events(db, "access.denied")[-1]
    assert denial.actor_id == user.id
    assert denial.details["action"] == "GET /audit-events"
    # audit:read is Admin-only by policy, so every other role lacks it.
    assert denial.details["reason"] == "missing_permission"
    assert denial.details["permission"] == "audit:read"


def test_audit_log_ignores_role_claims_in_the_token(client, make_user):
    member = make_user("member1")
    forged = create_access_token({"sub": "member1", "uid": member.id, "role": "admin"})

    response = client.get("/audit-events", headers={"Authorization": f"Bearer {forged}"})

    assert response.status_code == 403


# =========================================
# The audit API: contract, filters, pagination
# =========================================

def test_audit_log_lists_newest_first_with_safe_fields(client, db, make_user, login):
    admin = make_user("admin1", "admin")
    member = make_user("member1")
    headers = login("admin1")
    client.post(f"/users/{member.id}/deactivate", headers=headers)

    body = client.get("/audit-events", headers=headers).json()

    assert set(body) == {"events", "total", "page", "page_size"}
    assert body["total"] == 2
    newest = body["events"][0]
    assert newest["event_type"] == "user.deactivated"
    assert newest["actor"] == {"id": admin.id, "username": "admin1", "role": "admin"}
    assert newest["target"] == {"type": "user", "id": member.id, "username": "member1"}
    assert newest["details"] == {}
    assert datetime.fromisoformat(newest["occurred_at"]).tzinfo is not None
    assert body["events"][1]["event_type"] == "auth.sign_in"


def test_audit_log_paginates(client, db, make_user, login):
    make_user("admin1", "admin")
    for attempt in range(5):
        client.post("/login", json={"username": "admin1", "password": f"wrong-{attempt}-password"})
    headers = login("admin1")

    first = client.get("/audit-events?page_size=4", headers=headers).json()
    second = client.get("/audit-events?page_size=4&page=2", headers=headers).json()

    assert first["total"] == second["total"] == 6
    assert len(first["events"]) == 4 and len(second["events"]) == 2
    ids = [e["id"] for e in first["events"] + second["events"]]
    assert ids == sorted(ids, reverse=True)


def test_audit_log_filters(client, db, make_user, login):
    make_user("admin1", "admin")
    member = make_user("mem_ber%1")
    headers = login("admin1")
    client.post("/login", json={"username": "mem_ber%1", "password": "Wrong-Password-1"})
    client.post(f"/users/{member.id}/deactivate", headers=headers)

    def get(query):
        return client.get(f"/audit-events?{query}", headers=headers).json()

    assert [e["event_type"] for e in get("event_type=user.deactivated")["events"]] == ["user.deactivated"]
    assert {e["outcome"] for e in get("outcome=failure")["events"]} == {"failure"}
    # Matches actor or target, case-insensitively; % and _ are literal.
    assert get("q=MEM_BER%251")["total"] == 2
    assert get("q=mem%25ber")["total"] == 0
    assert get("q=admin1")["total"] == 2

    future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    params = lambda **kw: "&".join(f"{k}={v.replace('+', '%2B')}" for k, v in kw.items())
    assert get(params(since=past))["total"] == 3
    assert get(params(since=future))["total"] == 0
    assert get(params(until=past))["total"] == 0


@pytest.mark.parametrize(
    "query, status",
    [
        ("event_type=user.exploded", 422),
        ("outcome=maybe", 422),
        ("page=0", 422),
        ("page_size=101", 422),
        ("since=2026-01-02T00:00:00Z&until=2026-01-01T00:00:00Z", 400),
    ],
)
def test_audit_log_validates_queries(client, make_user, login, query, status):
    make_user("admin1", "admin")

    assert client.get(f"/audit-events?{query}", headers=login("admin1")).status_code == status


# =========================================
# Immutability
# =========================================

@pytest.mark.parametrize(
    "method, path",
    [
        ("post", "/audit-events"),
        ("put", "/audit-events"),
        ("patch", "/audit-events"),
        ("delete", "/audit-events"),
        ("get", "/audit-events/1"),
        ("put", "/audit-events/1"),
        ("patch", "/audit-events/1"),
        ("delete", "/audit-events/1"),
    ],
)
def test_the_api_offers_no_way_to_change_audit_events(client, make_user, login, method, path):
    make_user("admin1", "admin")

    response = client.request(method, path, headers=login("admin1"), json={"outcome": "success"})

    assert response.status_code in (404, 405)


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_events SET outcome = 'success'",
        "DELETE FROM audit_events",
        "TRUNCATE audit_events",
    ],
)
def test_the_database_rejects_changes_to_audit_events(make_user, login, statement):
    make_user("admin1", "admin")
    login("admin1")

    with pytest.raises(exc.DBAPIError, match="append-only"):
        with engine.begin() as connection:
            connection.execute(text(statement))

    with engine.connect() as connection:
        assert connection.execute(text("SELECT COUNT(*) FROM audit_events")).scalar_one() == 1
