import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.auth import create_access_token
from app.database import engine
from app.main import app
from app.migrations import ensure_role_permission_defaults
from app.models.access_request_model import AccessRequest
from app.models.audit_model import AuditEvent
from app.models.role_permission_model import RolePermissionGrant


# The access each role had before permissions became configurable; only
# Viewer / Auditor's unused audit:read is gone (the log always required Admin).
EXPECTED_DEFAULTS = {
    "admin": [
        "access_requests:review", "access_requests:submit", "activity:read",
        "audit:read", "roles:manage", "settings:manage", "users:manage", "users:read",
    ],
    "manager": ["access_requests:review", "access_requests:submit", "activity:read"],
    "member": ["access_requests:submit"],
    "viewer": ["activity:read"],
}

DEFAULT_GRANTS = {
    "manager": ["access_requests:submit", "access_requests:review", "activity:read"],
    "member": ["access_requests:submit"],
    "viewer": ["activity:read"],
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


def matrix(client, headers):
    response = client.get("/role-permissions", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def put(client, headers, grants, version=None):
    if version is None:
        version = matrix(client, headers)["version"]
    return client.put(
        "/role-permissions",
        headers=headers,
        json={"version": version, "grants": grants},
    )


def with_grants(**changes):
    grants = {role: list(codes) for role, codes in DEFAULT_GRANTS.items()}
    grants.update({role: list(codes) for role, codes in changes.items()})
    return grants


def cell(body, permission, role):
    row = next(row for row in body["permissions"] if row["permission"] == permission)
    return row["roles"][role]


# =========================================
# Defaults and migration
# =========================================

def test_startup_stores_every_configurable_cell_with_todays_defaults(db):
    rows = {
        (row.role, row.permission): row.granted
        for row in db.query(RolePermissionGrant).all()
    }

    assert rows == {
        ("manager", "users:read"): False,
        ("member", "users:read"): False,
        ("viewer", "users:read"): False,
        ("manager", "access_requests:submit"): True,
        ("manager", "access_requests:review"): True,
        ("member", "access_requests:review"): False,
        ("manager", "activity:read"): True,
        ("member", "activity:read"): False,
        ("viewer", "activity:read"): True,
    }
    assert all(row.updated_by_id is None for row in db.query(RolePermissionGrant).all())


def test_defaults_are_idempotent_and_never_overwrite_choices(db):
    with engine.begin() as connection:
        connection.execute(text(
            "UPDATE role_permission_grants SET granted = true"
            " WHERE role = 'viewer' AND permission = 'users:read'"
        ))
        connection.execute(text(
            "DELETE FROM role_permission_grants"
            " WHERE role = 'member' AND permission = 'access_requests:review'"
        ))

    added = ensure_role_permission_defaults(engine)

    assert added == ["member:access_requests:review"]
    assert ensure_role_permission_defaults(engine) == []
    db.expire_all()
    assert db.get(RolePermissionGrant, ("viewer", "users:read")).granted is True
    assert db.get(RolePermissionGrant, ("member", "access_requests:review")).granted is False


def test_missing_rows_fall_back_to_defaults(client, make_user, login):
    with engine.begin() as connection:
        connection.execute(text("DELETE FROM role_permission_grants"))

    make_user("mgr", "manager")
    profile = client.get("/profile", headers=login("mgr")).json()["user"]

    assert profile["permissions"] == EXPECTED_DEFAULTS["manager"]


@pytest.mark.parametrize("role", ["admin", "manager", "member", "viewer"])
def test_each_role_keeps_its_effective_permissions(client, make_user, login, role):
    make_user("someone", role)
    profile = client.get("/profile", headers=login("someone")).json()["user"]

    assert profile["permissions"] == EXPECTED_DEFAULTS[role]


@pytest.mark.parametrize("stored", ["Admin", "user"])
def test_legacy_role_values_resolve_through_the_policy(client, make_user, login, stored):
    make_user("legacy", stored)
    profile = client.get("/profile", headers=login("legacy")).json()["user"]

    expected = "admin" if stored == "Admin" else "member"
    assert profile["permissions"] == EXPECTED_DEFAULTS[expected]


# =========================================
# Admin-only endpoints
# =========================================

def test_endpoints_require_authentication(client):
    assert client.get("/role-permissions").status_code == 401
    assert client.put("/role-permissions", json={"version": "x", "grants": {}}).status_code == 401


@pytest.mark.parametrize("role", ["manager", "member", "viewer"])
def test_only_admins_can_read_or_change_permissions(client, db, make_user, login, role):
    make_user("someone", role)
    headers = login("someone")

    assert client.get("/role-permissions", headers=headers).status_code == 403
    response = client.put(
        "/role-permissions", headers=headers,
        json={"version": "x", "grants": with_grants(viewer=["activity:read", "users:read"])},
    )
    assert response.status_code == 403

    denials = events(db, "access.denied")
    assert [d.details["permission"] for d in denials] == ["roles:manage", "roles:manage"]
    assert db.get(RolePermissionGrant, ("viewer", "users:read")).granted is False


def test_role_claims_in_the_token_are_ignored(client, make_user):
    member = make_user("member1")
    forged = create_access_token({"sub": "member1", "uid": member.id, "role": "admin"})

    response = client.get("/role-permissions", headers={"Authorization": f"Bearer {forged}"})

    assert response.status_code == 403


def test_admin_with_pending_password_change_is_refused(client, make_user, login):
    make_user("fresh", "admin", must_change_password=True)

    assert client.get("/role-permissions", headers=login("fresh")).status_code == 403


def test_matrix_shows_editable_and_locked_cells(client, admin_headers):
    body = matrix(client, admin_headers)

    assert body["roles"] == ["admin", "manager", "member", "viewer"]
    assert [row["permission"] for row in body["permissions"]] == [
        "users:read", "users:manage", "access_requests:submit",
        "access_requests:review", "activity:read", "audit:read", "roles:manage",
        "settings:manage",
    ]

    assert cell(body, "users:read", "admin") == {
        "granted": True, "editable": False, "lock_reason": "admin_full_access",
    }
    assert cell(body, "users:read", "viewer") == {
        "granted": False, "editable": True, "lock_reason": None,
    }
    assert cell(body, "access_requests:review", "manager")["granted"] is True
    assert cell(body, "users:manage", "manager")["lock_reason"] == "admin_only"
    assert cell(body, "settings:manage", "viewer") == {
        "granted": False, "editable": False, "lock_reason": "admin_only",
    }
    assert cell(body, "audit:read", "viewer") == {
        "granted": False, "editable": False, "lock_reason": "audit_admin_only",
    }
    assert cell(body, "access_requests:submit", "member") == {
        "granted": True, "editable": False, "lock_reason": "member_submit_required",
    }
    assert cell(body, "access_requests:review", "viewer")["lock_reason"] == "viewer_read_only"
    assert body["updated_at"] is None and body["updated_by"] is None
    assert len(body["version"]) == 16


# =========================================
# Updates
# =========================================

def test_granting_takes_effect_immediately_for_existing_sessions(client, db, make_user, login, admin_headers):
    make_user("vic", "viewer")
    viewer_headers = login("vic")
    assert client.get("/users", headers=viewer_headers).status_code == 403

    response = put(client, admin_headers, with_grants(viewer=["activity:read", "users:read"]))

    assert response.status_code == 200, response.text
    assert cell(response.json(), "users:read", "viewer")["granted"] is True
    assert response.json()["updated_by"]["username"] == "root"
    # Same token, new policy.
    assert client.get("/users", headers=viewer_headers).status_code == 200
    profile = client.get("/profile", headers=viewer_headers).json()["user"]
    assert profile["permissions"] == ["activity:read", "users:read"]


def test_revoking_takes_effect_immediately(client, make_user, login, admin_headers):
    make_user("mgr", "manager")
    manager_headers = login("mgr")
    assert client.get("/access-requests", headers=manager_headers).status_code == 200

    response = put(client, admin_headers, with_grants(manager=["access_requests:submit"]))

    assert response.status_code == 200
    assert client.get("/access-requests", headers=manager_headers).status_code == 403
    assert client.get("/access-requests/summary", headers=manager_headers).status_code == 403

    put(client, admin_headers, with_grants(manager=[]))
    submit = client.post(
        "/access-requests", headers=manager_headers,
        json={"requested_role": "member", "reason": "Stepping back from the team."},
    )
    assert submit.status_code == 403


def test_users_read_does_not_grant_user_management(client, make_user, login, admin_headers):
    target = make_user("target")
    make_user("mgr", "manager")
    manager_headers = login("mgr")
    put(client, admin_headers, with_grants(manager=[*DEFAULT_GRANTS["manager"], "users:read"]))

    assert client.get("/users", headers=manager_headers).status_code == 200
    assert client.get(f"/users/{target.id}", headers=manager_headers).status_code == 200
    assert client.put(
        f"/users/{target.id}", headers=manager_headers, json={"role": "admin"}
    ).status_code == 403
    assert client.post(
        f"/users/{target.id}/deactivate", headers=manager_headers
    ).status_code == 403


def test_member_reviewers_keep_the_manager_and_self_rules(client, db, make_user, login, admin_headers):
    member = make_user("mem")
    other = make_user("other")
    put(client, admin_headers, with_grants(member=["access_requests:submit", "access_requests:review"]))

    for requester, role in [(member, "viewer"), (other, "manager")]:
        response = client.post(
            "/access-requests", headers=login(requester.username),
            json={"requested_role": role, "reason": "Covering for a colleague."},
        )
        assert response.status_code == 201
    own, manager_request = db.query(AccessRequest).order_by(AccessRequest.id).all()

    member_headers = login("mem")
    assert client.get("/access-requests", headers=member_headers).status_code == 200
    assert client.post(f"/access-requests/{own.id}/approve", headers=member_headers).status_code == 403
    assert client.post(
        f"/access-requests/{manager_request.id}/approve", headers=member_headers
    ).status_code == 403
    db.refresh(other)
    assert other.role == "member"


def test_saving_the_same_matrix_changes_nothing(client, db, admin_headers):
    response = put(client, admin_headers, with_grants())

    assert response.status_code == 200
    assert events(db, "role.permissions_changed") == []
    assert response.json()["updated_at"] is None


def test_each_changed_role_is_audited_with_before_and_after(client, db, admin_headers):
    response = put(
        client, admin_headers,
        with_grants(
            manager=[*DEFAULT_GRANTS["manager"], "users:read"],
            viewer=["activity:read", "users:read"],
        ),
    )
    assert response.status_code == 200

    changed = events(db, "role.permissions_changed")
    assert [(e.target_type, e.target_username) for e in changed] == [
        ("role", "manager"), ("role", "viewer"),
    ]
    assert changed[0].actor_username == "root"
    assert changed[0].actor_role == "admin"
    assert changed[0].outcome == "success"
    assert changed[0].details == {
        "role": "manager",
        "from_permissions": "access_requests:review,access_requests:submit,activity:read",
        "to_permissions": "access_requests:review,access_requests:submit,activity:read,users:read",
    }
    assert changed[1].details == {
        "role": "viewer", "from_permissions": "activity:read",
        "to_permissions": "activity:read,users:read",
    }

    listed = client.get(
        "/audit-events", headers=admin_headers, params={"event_type": "role.permissions_changed"}
    ).json()["events"]
    assert listed[0]["target"] == {"type": "role", "id": None, "username": "viewer"}


INVALID_UPDATES = [
    ({"admin": [], **DEFAULT_GRANTS}, "Admin permissions can't be changed"),
    ({"manager": DEFAULT_GRANTS["manager"], "member": DEFAULT_GRANTS["member"]}, "viewer missing"),
    ({**DEFAULT_GRANTS, "owner": []}, "Unknown role: owner"),
    (with_grants(viewer=["users:write"]), "Unknown permission: users:write"),
    (with_grants(viewer=["activity:read", "activity:read_all"]), "Unknown permission: activity:read_all"),
    (with_grants(viewer=["audit:read"]), "audit:read can't be granted to viewer"),
    (with_grants(manager=[*DEFAULT_GRANTS["manager"], "audit:read"]), "audit:read can't be granted to manager"),
    (with_grants(manager=[*DEFAULT_GRANTS["manager"], "users:manage"]), "users:manage can't be granted to manager"),
    (with_grants(member=["access_requests:submit", "roles:manage"]), "roles:manage can't be granted to member"),
    (with_grants(viewer=["activity:read", "settings:manage"]), "settings:manage can't be granted to viewer"),
    (with_grants(member=[]), "access_requests:submit can't be removed from member"),
    (with_grants(viewer=["access_requests:submit"]), "Viewer / Auditor is read-only"),
    (with_grants(viewer=["access_requests:review"]), "access_requests:review can't be granted to viewer"),
]


@pytest.mark.parametrize("grants, message", INVALID_UPDATES)
def test_invalid_updates_are_rejected_without_changes(client, db, admin_headers, grants, message):
    before = matrix(client, admin_headers)

    response = put(client, admin_headers, grants, version=before["version"])

    assert response.status_code == 422
    assert message in response.json()["detail"]
    assert matrix(client, admin_headers) == before
    assert events(db, "role.permissions_changed") == []


@pytest.mark.parametrize(
    "body",
    [
        {"grants": DEFAULT_GRANTS},
        {"version": "", "grants": DEFAULT_GRANTS},
        {"version": "x"},
        {"version": "x", "grants": {"manager": "users:read", "member": [], "viewer": []}},
    ],
)
def test_malformed_updates_are_rejected(client, admin_headers, body):
    assert client.put("/role-permissions", headers=admin_headers, json=body).status_code == 422


def test_stale_updates_are_rejected(client, db, admin_headers):
    stale = matrix(client, admin_headers)["version"]
    assert put(client, admin_headers, with_grants(viewer=["activity:read", "users:read"])).status_code == 200

    response = put(client, admin_headers, with_grants(member=["access_requests:submit", "users:read"]), version=stale)

    assert response.status_code == 409
    assert db.get(RolePermissionGrant, ("member", "users:read")).granted is False
    assert len(events(db, "role.permissions_changed")) == 1


def test_a_failed_update_changes_nothing(db, admin_headers, monkeypatch):
    import app.routes.role_permission_routes as routes

    def failing_record_event(*args, **kwargs):
        raise RuntimeError("audit store unavailable")

    unsafe_client = TestClient(app, raise_server_exceptions=False)
    version = matrix(unsafe_client, admin_headers)["version"]
    monkeypatch.setattr(routes, "record_event", failing_record_event)

    response = put(
        unsafe_client, admin_headers,
        with_grants(viewer=["activity:read", "users:read"], member=["access_requests:submit", "users:read"]),
        version=version,
    )

    assert response.status_code == 500
    db.expire_all()
    assert db.get(RolePermissionGrant, ("viewer", "users:read")).granted is False
    assert db.get(RolePermissionGrant, ("member", "users:read")).granted is False
    assert db.get(RolePermissionGrant, ("viewer", "users:read")).updated_by_id is None
