from datetime import datetime, timedelta, timezone

import pytest

from app.audit import AuditEventType, AuditOutcome, record_event
from app.auth import create_access_token
from app.models.audit_model import AuditEvent
from app.routes.activity_routes import ACTIVITY_EVENT_TYPES


def events(db, event_type=None):
    db.expire_all()
    query = db.query(AuditEvent)
    if event_type:
        query = query.filter(AuditEvent.event_type == event_type)
    return query.order_by(AuditEvent.id).all()


def activity(client, headers, **params):
    response = client.get("/activity", headers=headers, params=params)
    assert response.status_code == 200, response.text
    return response.json()


def grants(client, admin_headers, **changes):
    """Save the matrix with some roles' permissions replaced."""
    body = client.get("/role-permissions", headers=admin_headers).json()
    current = {
        role: [row["permission"] for row in body["permissions"] if row["roles"][role]["granted"]]
        for role in ("manager", "member", "viewer")
    }
    current.update(changes)
    response = client.put(
        "/role-permissions", headers=admin_headers,
        json={"version": body["version"], "grants": current},
    )
    assert response.status_code == 200, response.text


@pytest.fixture
def admin_headers(make_user, login):
    make_user("root", "admin")
    return login("root")


# =========================================
# Access
# =========================================

def test_requires_authentication(client):
    assert client.get("/activity").status_code == 401


@pytest.mark.parametrize("role", ["admin", "manager", "viewer"])
def test_default_readers(client, make_user, login, role):
    make_user("reader", role)

    assert client.get("/activity", headers=login("reader")).status_code == 200


def test_members_cannot_read_activity_by_default(client, db, make_user, login):
    member = make_user("mem")

    response = client.get("/activity", headers=login("mem"))

    assert response.status_code == 403
    denial = events(db, "access.denied")[-1]
    assert denial.actor_id == member.id
    assert denial.details == {
        "permission": "activity:read",
        "action": "GET /activity",
        "reason": "missing_permission",
    }


def test_activity_does_not_widen_audit_log_access(client, make_user, login):
    for role in ("manager", "viewer"):
        make_user(role, role)
        headers = login(role)
        assert client.get("/activity", headers=headers).status_code == 200
        assert client.get("/audit-events", headers=headers).status_code == 403


def test_role_claims_in_the_token_are_ignored(client, make_user):
    member = make_user("mem")
    forged = create_access_token({"sub": "mem", "uid": member.id, "role": "admin"})

    assert client.get("/activity", headers={"Authorization": f"Bearer {forged}"}).status_code == 403


def test_pending_password_change_blocks_activity(client, make_user, login):
    make_user("fresh", "manager", must_change_password=True)

    assert client.get("/activity", headers=login("fresh")).status_code == 403


def test_policy_changes_apply_immediately(client, make_user, login, admin_headers):
    make_user("vic", "viewer")
    make_user("mem")
    viewer_headers, member_headers = login("vic"), login("mem")

    grants(client, admin_headers, viewer=[], member=["access_requests:submit", "activity:read"])

    assert client.get("/activity", headers=viewer_headers).status_code == 403
    assert client.get("/activity", headers=member_headers).status_code == 200
    assert "activity:read" in client.get("/profile", headers=member_headers).json()["user"]["permissions"]


def test_roles_matrix_offers_activity_read(client, admin_headers):
    body = client.get("/role-permissions", headers=admin_headers).json()
    row = next(row for row in body["permissions"] if row["permission"] == "activity:read")

    assert row["roles"] == {
        "admin": {"granted": True, "editable": False, "lock_reason": "admin_full_access"},
        "manager": {"granted": True, "editable": True, "lock_reason": None},
        "member": {"granted": False, "editable": True, "lock_reason": None},
        "viewer": {"granted": True, "editable": True, "lock_reason": None},
    }


def test_retired_activity_permissions_are_rejected(client, admin_headers):
    body = client.get("/role-permissions", headers=admin_headers).json()

    response = client.put(
        "/role-permissions", headers=admin_headers,
        json={
            "version": body["version"],
            "grants": {
                "manager": ["access_requests:submit", "access_requests:review", "activity:read_team"],
                "member": ["access_requests:submit"],
                "viewer": ["activity:read"],
            },
        },
    )

    assert response.status_code == 422


# =========================================
# Coverage: real actions appear in the feed
# =========================================

def test_meaningful_events_appear_and_routine_reads_do_not(client, db, make_user, login, admin_headers):
    target = make_user("target")
    make_user("mgr", "manager")

    # Sign-ins: success, wrong password, unknown username.
    login("target")
    client.post("/login", json={"username": "target", "password": "wrong-password"})
    client.post("/login", json={"username": "no-such-user", "password": "whatever-it-is"})
    # User management and a role change.
    created = client.post("/users", headers=admin_headers, json={"username": "newbie", "role": "member"})
    assert created.status_code == 200
    changed = client.put(
        f"/users/{target.id}", headers=admin_headers, json={"username": "target", "role": "viewer"}
    )
    assert changed.status_code == 200, changed.text
    client.post(f"/users/{target.id}/deactivate", headers=admin_headers)
    client.post(f"/users/{target.id}/reactivate", headers=admin_headers)
    # A denial, a request and its decision, and a permission change.
    mgr_headers = login("mgr")
    client.get("/users", headers=mgr_headers)
    submit = client.post(
        "/access-requests", headers=mgr_headers,
        json={"requested_role": "member", "reason": "Stepping back from the team."},
    )
    client.post(f"/access-requests/{submit.json()['request']['id']}/decline", headers=admin_headers)
    grants(client, admin_headers, member=["access_requests:submit", "users:read"])

    recorded = len(events(db))

    # Routine reads add nothing.
    for path in ("/activity", "/profile", "/users", "/audit-events", "/role-permissions", "/access-requests"):
        client.get(path, headers=admin_headers)
    assert len(events(db)) == recorded

    feed = activity(client, admin_headers, page_size=100)["events"]
    seen = {(event["event_type"], event["outcome"]) for event in feed}
    assert {
        ("auth.sign_in", "success"),
        ("auth.sign_in", "failure"),
        ("user.created", "success"),
        ("user.role_changed", "success"),
        ("user.deactivated", "success"),
        ("user.reactivated", "success"),
        ("access.denied", "denied"),
        ("access_request.submitted", "success"),
        ("access_request.declined", "success"),
        ("role.permissions_changed", "success"),
    } <= seen
    # Everything recorded is in the feed.
    assert activity(client, admin_headers)["total"] == recorded


def test_feed_is_display_safe(client, db, make_user, login, admin_headers):
    target = make_user("target")
    created = client.post("/users", headers=admin_headers, json={"username": "newbie", "role": "member"})
    temporary_password = created.json().get("temporary_password")
    client.post("/login", json={"username": "target", "password": "Sup3r-Secret-Typo!"})
    client.post("/login", json={"username": "Sup3r-Secret-Typo!", "password": "x" * 12})
    make_user("mgr", "manager")
    mgr_headers = login("mgr")
    client.post(f"/users/{target.id}/deactivate", headers=mgr_headers)
    submit = client.post(
        "/access-requests", headers=mgr_headers,
        json={"requested_role": "member", "reason": "Private reason text 4242"},
    )
    client.post(
        f"/access-requests/{submit.json()['request']['id']}/approve", headers=admin_headers,
        json={"note": "Private note text 9191"},
    )

    response = client.get("/activity", headers=admin_headers, params={"page_size": 100})
    raw = response.text

    for secret in [temporary_password, "Sup3r-Secret-Typo!", "Private reason text", "Private note text",
                   "Bearer", "eyJ", "hashed_password"]:
        if secret:
            assert secret not in raw

    allowed_details = {
        "reason", "role", "from_role", "to_role", "requested_role",
        "from_username", "to_username", "permission", "from_permissions", "to_permissions",
    }
    for event in response.json()["events"]:
        assert set(event) == {"id", "occurred_at", "event_type", "outcome", "actor", "target", "details"}
        assert set(event["details"]) <= allowed_details
        if event["actor"]:
            assert set(event["actor"]) == {"username", "role"}
        if event["target"]:
            assert set(event["target"]) == {"type", "username"}

    # The audit log keeps the full detail the feed leaves out.
    denial = activity(client, admin_headers, event_type="access.denied")["events"][0]
    assert denial["details"] == {"permission": "users:manage", "reason": "missing_permission"}
    audit_denial = client.get(
        "/audit-events", headers=admin_headers, params={"event_type": "access.denied"}
    ).json()["events"][0]
    assert audit_denial["details"]["action"] == "POST /users/{user_id}/deactivate"
    assert audit_denial["actor"]["id"] is not None


def test_failed_sign_in_for_unknown_user_has_no_actor_or_target(client, admin_headers):
    client.post("/login", json={"username": "ghost", "password": "whatever-it-is"})

    event = activity(client, admin_headers, event_type="auth.sign_in", outcome="failure")["events"][0]

    assert event["actor"] is None
    assert event["target"] is None
    assert event["details"] == {"reason": "invalid_credentials"}


def test_every_recorded_event_type_is_in_the_feed():
    assert ACTIVITY_EVENT_TYPES == frozenset(AuditEventType)


# =========================================
# Filters and pagination
# =========================================

@pytest.fixture
def seeded(db, admin_headers):
    """Recorded events at fixed times (the admin's own sign-in is first)."""
    base = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)
    rows = [
        (AuditEventType.SIGN_IN, AuditOutcome.SUCCESS, "alice", 0),
        (AuditEventType.SIGN_IN, AuditOutcome.FAILURE, "bob", 1),
        (AuditEventType.ACCESS_DENIED, AuditOutcome.DENIED, "carol", 2),
        (AuditEventType.ROLE_CHANGED, AuditOutcome.SUCCESS, "alice", 3),
        (AuditEventType.SIGN_IN, AuditOutcome.SUCCESS, "dave", 4),
    ]
    for event_type, outcome, username, days in rows:
        event = record_event(
            db, event_type, outcome,
            actor=type("Actor", (), {"id": None, "username": username, "role": "member"})(),
        )
        event.occurred_at = base + timedelta(days=days)
    db.commit()
    return base


def test_filters_by_type_outcome_and_username(client, admin_headers, seeded):
    by_type = activity(client, admin_headers, event_type="auth.sign_in")
    assert {e["actor"]["username"] for e in by_type["events"]} >= {"alice", "bob", "dave"}
    assert all(e["event_type"] == "auth.sign_in" for e in by_type["events"])

    failures = activity(client, admin_headers, outcome="failure")
    assert [e["actor"]["username"] for e in failures["events"]] == ["bob"]

    alice = activity(client, admin_headers, q="ALI")
    assert [e["event_type"] for e in alice["events"]] == ["user.role_changed", "auth.sign_in"]

    assert activity(client, admin_headers, q="%")["total"] == 0


def test_filters_by_date_range(client, admin_headers, seeded):
    window = activity(
        client, admin_headers,
        since=(seeded + timedelta(days=1)).isoformat(),
        until=(seeded + timedelta(days=3)).isoformat(),
    )

    assert [e["actor"]["username"] for e in window["events"]] == ["carol", "bob"]


def test_pagination_is_newest_first(client, admin_headers, seeded):
    first = activity(client, admin_headers, page=1, page_size=2)
    second = activity(client, admin_headers, page=2, page_size=2)

    assert first["total"] == 6  # five seeded events and the admin's sign-in
    assert first["page"] == 1 and first["page_size"] == 2
    times = [e["occurred_at"] for e in first["events"] + second["events"]]
    assert times == sorted(times, reverse=True)
    assert {e["id"] for e in first["events"]}.isdisjoint({e["id"] for e in second["events"]})


@pytest.mark.parametrize(
    "params, status",
    [
        ({"since": "2026-10-05T00:00:00Z", "until": "2026-10-01T00:00:00Z"}, 400),
        ({"event_type": "user.exploded"}, 422),
        ({"outcome": "maybe"}, 422),
        ({"page": 0}, 422),
        ({"page_size": 101}, 422),
        ({"q": "x" * 101}, 422),
    ],
)
def test_invalid_filters_are_rejected(client, admin_headers, params, status):
    assert client.get("/activity", headers=admin_headers, params=params).status_code == status
