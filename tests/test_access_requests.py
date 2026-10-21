from collections import Counter
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import exc

from app.audit import AuditEventType
from app.demo_seed import (
    SeedNotAllowed,
    ensure_demo_admin,
    remove_demo_users,
    seed_demo_access_requests,
    seed_demo_users,
)
from app.main import app
from app.models.access_request_model import AccessRequest
from app.models.audit_model import AuditEvent
from app.models.user_model import User


REASON = "Leading the onboarding project this quarter"


def submit(client, headers, role="manager", reason=REASON):
    return client.post("/access-requests", headers=headers,
                       json={"requested_role": role, "reason": reason})


def audit(db, event_type=None):
    db.expire_all()
    query = db.query(AuditEvent).order_by(AuditEvent.id)
    if event_type:
        query = query.filter(AuditEvent.event_type == event_type)
    return query.all()


def role_of(db, user_id):
    db.expire_all()
    return db.get(User, user_id).role


@pytest.fixture
def org(make_user, login):
    """An admin, a manager and two members, each signed in."""
    people = {
        "admin": make_user("ada.admin", "admin"),
        "manager": make_user("max.manager", "manager"),
        "member": make_user("mia.member", "member"),
        "member2": make_user("mo.member", "member"),
    }
    headers = {key: login(user.username) for key, user in people.items()}
    return people, headers


# =========================================
# Submission
# =========================================

def test_member_submits_a_request(client, db, org):
    people, headers = org

    response = submit(client, headers["member"], "viewer")

    assert response.status_code == 201
    request = response.json()["request"]
    assert request["status"] == "pending"
    assert request["requested_role"] == "viewer"
    assert request["reason"] == REASON
    assert request["decision"] is None
    assert request["requester"] == {
        "id": people["member"].id, "username": "mia.member", "role_at_submission": "member",
        "current_username": "mia.member", "current_role": "member",
    }
    assert request["can_decide"] is False
    assert request["decision_block_reason"] == "missing_permission"

    [event] = audit(db, "access_request.submitted")
    assert (event.actor_id, event.target_id, event.outcome) == (people["member"].id, people["member"].id, "success")
    assert event.details == {"request_id": request["id"], "requested_role": "viewer", "role": "member"}


def test_free_text_never_reaches_the_audit_log(client, db, org):
    _, headers = org
    request_id = submit(client, headers["member"], "viewer", reason="Secret project codename BLUEBIRD").json()["request"]["id"]
    client.post(f"/access-requests/{request_id}/decline", headers=headers["manager"],
                json={"note": "Ask again after the BLUEBIRD launch"})

    stored = str([(e.details, e.actor_username, e.target_username) for e in audit(db)])
    assert "BLUEBIRD" not in stored


def test_managers_may_request_a_different_role(client, org):
    _, headers = org

    assert submit(client, headers["manager"], "viewer").status_code == 201


def test_viewers_cannot_submit(client, db, make_user, login):
    viewer = make_user("val.viewer", "viewer")

    response = submit(client, login("val.viewer"), "member")

    assert response.status_code == 403
    [denial] = audit(db, "access.denied")
    assert denial.actor_id == viewer.id
    assert denial.details["permission"] == "access_requests:submit"


def test_admins_cannot_submit(client, org):
    _, headers = org

    response = submit(client, headers["admin"], "manager")

    assert response.status_code == 400
    assert response.json()["detail"] == "Administrators already have full access"


@pytest.mark.parametrize(
    "payload",
    [
        {"requested_role": "admin", "reason": REASON},
        {"requested_role": "Admin", "reason": REASON},
        {"requested_role": "superuser", "reason": REASON},
        {"requested_role": "manager", "reason": "  "},
        {"requested_role": "manager", "reason": "x" * 501},
        {"requested_role": "manager"},
    ],
)
def test_submission_validation(client, org, payload):
    _, headers = org

    assert client.post("/access-requests", headers=headers["member"], json=payload).status_code == 422


def test_cannot_request_your_current_role(client, org):
    _, headers = org

    response = submit(client, headers["member"], "member")

    assert response.status_code == 400
    assert response.json()["detail"] == "You already have this role"


def test_one_pending_request_at_a_time(client, org):
    _, headers = org
    first = submit(client, headers["member"], "viewer").json()["request"]

    duplicate = submit(client, headers["member"], "manager")
    assert duplicate.status_code == 409
    assert duplicate.json()["detail"] == "You already have a pending access request"

    client.post(f"/access-requests/{first['id']}/decline", headers=headers["manager"])
    assert submit(client, headers["member"], "manager").status_code == 201


def test_the_database_also_enforces_one_pending_request(db, org):
    people, _ = org
    member = people["member"]

    def pending():
        return AccessRequest(requester_id=member.id, requester_username=member.username,
                             requester_role="member", requested_role="viewer",
                             reason=REASON, status="pending")

    db.add(pending())
    db.commit()
    db.add(pending())
    with pytest.raises(exc.IntegrityError):
        db.commit()
    db.rollback()


def test_my_requests_lists_only_your_own(client, org):
    _, headers = org
    submit(client, headers["member"], "viewer")
    submit(client, headers["member2"], "manager")

    mine = client.get("/access-requests/mine", headers=headers["member"]).json()

    assert mine["total"] == 1
    assert [r["requester"]["username"] for r in mine["requests"]] == ["mia.member"]


# =========================================
# Reviewer access
# =========================================

ENDPOINTS = [
    ("post", "/access-requests"),
    ("get", "/access-requests"),
    ("get", "/access-requests/mine"),
    ("get", "/access-requests/summary"),
    ("post", "/access-requests/1/approve"),
    ("post", "/access-requests/1/decline"),
]


@pytest.mark.parametrize("method, path", ENDPOINTS)
def test_every_endpoint_requires_sign_in(client, method, path):
    assert client.request(method, path, json={}).status_code == 401


@pytest.mark.parametrize("role", ["member", "viewer"])
def test_only_reviewers_see_the_queue_or_decide(client, make_user, login, org, role):
    _, headers = org
    request_id = submit(client, headers["member2"], "viewer").json()["request"]["id"]
    make_user("someone", role)
    someone = login("someone")

    assert client.get("/access-requests", headers=someone).status_code == 403
    assert client.get("/access-requests/summary", headers=someone).status_code == 403
    assert client.post(f"/access-requests/{request_id}/approve", headers=someone).status_code == 403


# =========================================
# Decisions
# =========================================

def test_manager_approves_and_the_role_changes_atomically(client, db, org):
    people, headers = org
    member_headers = headers["member"]
    request_id = submit(client, member_headers, "viewer").json()["request"]["id"]

    response = client.post(f"/access-requests/{request_id}/approve", headers=headers["manager"],
                           json={"note": "  Approved for the audit project.  "})

    assert response.status_code == 200
    request = response.json()["request"]
    assert request["status"] == "approved"
    assert request["requested_role"] == "viewer" and request["reason"] == REASON
    assert request["decision"]["note"] == "Approved for the audit project."
    assert request["decision"]["reviewer"] == {"id": people["manager"].id, "username": "max.manager", "role": "manager"}
    assert datetime.fromisoformat(request["decision"]["decided_at"]).tzinfo is not None
    assert role_of(db, people["member"].id) == "viewer"

    # The requester's existing session immediately has the new permissions.
    profile = client.get("/profile", headers=member_headers).json()["user"]
    assert profile["permissions"] == ["activity:read"]

    events = [(e.event_type, e.details) for e in audit(db) if e.event_type != "auth.sign_in"]
    assert events[-2:] == [
        ("user.role_changed", {"from_role": "member", "to_role": "viewer",
                               "reason": "access_request", "request_id": request_id}),
        ("access_request.approved", {"request_id": request_id, "requested_role": "viewer"}),
    ]


def test_decline_leaves_the_role_unchanged(client, db, org):
    people, headers = org
    request_id = submit(client, headers["member"], "viewer").json()["request"]["id"]

    response = client.post(f"/access-requests/{request_id}/decline", headers=headers["manager"])

    assert response.status_code == 200
    assert response.json()["request"]["status"] == "declined"
    assert response.json()["request"]["decision"]["note"] is None
    assert role_of(db, people["member"].id) == "member"
    assert audit(db, "user.role_changed") == []
    assert [e.outcome for e in audit(db, "access_request.declined")] == ["success"]


def test_managers_cannot_decide_manager_access(client, db, org):
    people, headers = org
    request_id = submit(client, headers["member"], "manager").json()["request"]["id"]

    queue = client.get("/access-requests", headers=headers["manager"]).json()["requests"]
    assert (queue[0]["can_decide"], queue[0]["decision_block_reason"]) == (False, "manager_requires_admin")

    for action in ["approve", "decline"]:
        response = client.post(f"/access-requests/{request_id}/{action}", headers=headers["manager"])
        assert response.status_code == 403
        assert response.json()["detail"] == "Only administrators can decide requests for Manager access"

    assert [(e.outcome, e.details["reason"]) for e in audit(db, "access_request.approved")] == [
        ("denied", "manager_requires_admin")
    ]
    assert role_of(db, people["member"].id) == "member"

    approved = client.post(f"/access-requests/{request_id}/approve", headers=headers["admin"])
    assert approved.status_code == 200
    assert role_of(db, people["member"].id) == "manager"


def test_nobody_reviews_their_own_request(client, db, org):
    people, headers = org
    request_id = submit(client, headers["manager"], "viewer").json()["request"]["id"]

    queue = client.get("/access-requests", headers=headers["manager"]).json()["requests"]
    assert queue[0]["decision_block_reason"] == "own_request"

    response = client.post(f"/access-requests/{request_id}/approve", headers=headers["manager"])

    assert response.status_code == 403
    assert response.json()["detail"] == "You can't review your own access request"
    assert role_of(db, people["manager"].id) == "manager"


def test_a_request_is_decided_only_once(client, db, org):
    people, headers = org
    request_id = submit(client, headers["member"], "viewer").json()["request"]["id"]
    client.post(f"/access-requests/{request_id}/approve", headers=headers["manager"])

    again = client.post(f"/access-requests/{request_id}/approve", headers=headers["admin"])
    reverse = client.post(f"/access-requests/{request_id}/decline", headers=headers["admin"])

    assert (again.status_code, reverse.status_code) == (409, 409)
    assert reverse.json()["detail"] == "This access request has already been approved"
    assert role_of(db, people["member"].id) == "viewer"
    assert len(audit(db, "access_request.approved")) == 1


def test_unknown_request_returns_404(client, org):
    _, headers = org

    assert client.post("/access-requests/999/approve", headers=headers["admin"]).status_code == 404


def test_approval_rechecks_the_requester(client, db, org):
    people, headers = org
    member_id = people["member"].id
    request_id = submit(client, headers["member"], "viewer").json()["request"]["id"]

    client.post(f"/users/{member_id}/deactivate", headers=headers["admin"])
    inactive = client.post(f"/access-requests/{request_id}/approve", headers=headers["admin"])
    assert (inactive.status_code, inactive.json()["detail"]) == (409, "The requester's account is deactivated")

    client.post(f"/users/{member_id}/reactivate", headers=headers["admin"])
    client.put(f"/users/{member_id}", headers=headers["admin"], json={"username": "mia.member", "role": "admin"})
    promoted = client.post(f"/access-requests/{request_id}/approve", headers=headers["admin"])
    assert (promoted.status_code, promoted.json()["detail"]) == (409, "The requester is now an administrator")

    db.expire_all()
    assert db.get(AccessRequest, request_id).status == "pending"


def test_history_survives_rename_and_deletion(client, db, org):
    people, headers = org
    member_id = people["member"].id
    request_id = submit(client, headers["member"], "viewer").json()["request"]["id"]

    client.put(f"/users/{member_id}", headers=headers["admin"], json={"username": "mia.renamed", "role": "member"})
    renamed = client.get("/access-requests", headers=headers["admin"]).json()["requests"][0]["requester"]
    assert (renamed["username"], renamed["current_username"]) == ("mia.member", "mia.renamed")

    client.post(f"/users/{member_id}/deactivate", headers=headers["admin"])
    client.delete(f"/users/{member_id}", headers=headers["admin"])

    cannot_approve = client.post(f"/access-requests/{request_id}/approve", headers=headers["admin"])
    assert cannot_approve.status_code == 409
    declined = client.post(f"/access-requests/{request_id}/decline", headers=headers["admin"])
    assert declined.status_code == 200
    requester = declined.json()["request"]["requester"]
    assert requester == {"id": member_id, "username": "mia.member", "role_at_submission": "member",
                         "current_username": None, "current_role": None}
    assert audit(db, "access_request.declined")[-1].target_username == "mia.member"


def test_approving_a_role_the_requester_already_has_records_no_role_change(client, db, org):
    people, headers = org
    member_id = people["member"].id
    request_id = submit(client, headers["member"], "viewer").json()["request"]["id"]
    client.put(f"/users/{member_id}", headers=headers["admin"], json={"username": "mia.member", "role": "viewer"})
    role_changes_before = len(audit(db, "user.role_changed"))

    response = client.post(f"/access-requests/{request_id}/approve", headers=headers["admin"])

    assert response.json()["request"]["status"] == "approved"
    assert len(audit(db, "user.role_changed")) == role_changes_before


def test_a_failed_approval_is_rolled_back_completely(db, org, monkeypatch):
    people, headers = org
    unsafe_client = TestClient(app, raise_server_exceptions=False)
    request_id = submit(unsafe_client, headers["member"], "viewer").json()["request"]["id"]
    events_before = len(audit(db))

    import app.routes.access_request_routes as routes
    real_record_event = routes.record_event

    def failing_record_event(db_session, event_type, *args, **kwargs):
        if event_type == AuditEventType.ACCESS_REQUEST_APPROVED:
            raise RuntimeError("simulated audit failure")
        return real_record_event(db_session, event_type, *args, **kwargs)

    monkeypatch.setattr(routes, "record_event", failing_record_event)

    response = unsafe_client.post(f"/access-requests/{request_id}/approve", headers=headers["manager"])

    assert response.status_code == 500
    db.expire_all()
    assert role_of(db, people["member"].id) == "member"
    assert db.get(AccessRequest, request_id).status == "pending"
    assert db.get(AccessRequest, request_id).reviewer_id is None
    assert len(audit(db)) == events_before


# =========================================
# Queue, filters, pagination, summary
# =========================================

def test_queue_filters_and_pagination(client, db, make_user, login, org):
    _, headers = org
    ids = {}
    for name, role in [("ana_1", "viewer"), ("ben%2", "manager"), ("cy.3", "viewer"), ("di.4", "manager")]:
        make_user(name, "member")
        ids[name] = submit(client, login(name), role).json()["request"]["id"]
    client.post(f"/access-requests/{ids['ana_1']}/approve", headers=headers["manager"])
    client.post(f"/access-requests/{ids['cy.3']}/decline", headers=headers["manager"])

    def get(query=""):
        response = client.get(f"/access-requests?{query}", headers=headers["manager"])
        assert response.status_code == 200, response.text
        return response.json()

    everything = get()
    assert everything["total"] == 4
    assert [r["id"] for r in everything["requests"]] == sorted(ids.values(), reverse=True)

    assert {r["id"] for r in get("status=pending")["requests"]} == {ids["ben%2"], ids["di.4"]}
    assert {r["id"] for r in get("requested_role=viewer")["requests"]} == {ids["ana_1"], ids["cy.3"]}
    assert [r["id"] for r in get("q=BEN%252")["requests"]] == [ids["ben%2"]]
    assert get("q=a_1")["total"] == 1
    assert get("q=b%25%25")["total"] == 0

    page = get("page_size=3&page=2")
    assert (page["total"], len(page["requests"]), page["page"]) == (4, 1, 2)

    past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat().replace("+", "%2B")
    future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+", "%2B")
    assert get(f"since={past}")["total"] == 4
    assert get(f"since={future}")["total"] == 0
    assert get(f"until={past}")["total"] == 0


@pytest.mark.parametrize(
    "query, status",
    [
        ("status=cancelled", 422),
        ("requested_role=admin", 422),
        ("page=0", 422),
        ("page_size=101", 422),
        ("since=2026-01-02T00:00:00Z&until=2026-01-01T00:00:00Z", 400),
    ],
)
def test_queue_validates_queries(client, org, query, status):
    _, headers = org

    assert client.get(f"/access-requests?{query}", headers=headers["admin"]).status_code == status


def test_summary_counts_pending_requests(client, make_user, login, org):
    _, headers = org
    request_ids = []
    for index in range(7):
        make_user(f"member{index}", "member")
        request_ids.append(submit(client, login(f"member{index}"), "viewer").json()["request"]["id"])
    client.post(f"/access-requests/{request_ids[0]}/decline", headers=headers["manager"])

    summary = client.get("/access-requests/summary", headers=headers["manager"]).json()

    assert summary["pending_total"] == 6
    assert [r["id"] for r in summary["recent"]] == list(reversed(request_ids[2:]))
    assert all(r["status"] == "pending" for r in summary["recent"])


# =========================================
# Demo data
# =========================================

DEMO_ENV = {"APP_ENV": "demo", "DATABASE_URL": "postgresql://localhost/demo_test_db"}


def test_demo_request_history_is_synthetic_deterministic_and_preserves_roles(db):
    seed_demo_users(db, environ=DEMO_ENV)
    ensure_demo_admin(db, environ=DEMO_ENV)
    roles_before = Counter(u.role for u in db.query(User).all())

    created = seed_demo_access_requests(db, environ=DEMO_ENV)

    requests = db.query(AccessRequest).all()
    assert created == len(requests) == 24
    assert all(r.is_seed for r in requests)
    assert Counter(r.status for r in requests) == {"approved": 10, "declined": 6, "pending": 8}
    assert Counter(u.role for u in db.query(User).all()) == roles_before

    pending_requesters = [r.requester_id for r in requests if r.status == "pending"]
    assert len(pending_requesters) == len(set(pending_requesters))
    for request in requests:
        assert request.requested_role != "admin"
        if request.status != "pending" and request.requested_role == "manager":
            assert request.reviewer_role == "admin"
        if request.status == "approved":
            requester = db.get(User, request.requester_id)
            assert requester.role == request.requested_role

    assert seed_demo_access_requests(db, environ=DEMO_ENV) == 0

    remove_demo_users(db, environ=DEMO_ENV)
    assert db.query(AccessRequest).count() == 0


def test_demo_request_history_is_refused_outside_demo_environments(db):
    with pytest.raises(SeedNotAllowed):
        seed_demo_access_requests(db, environ={"APP_ENV": "production"})


def test_requests_submitted_in_demo_mode_are_demo_data(client, make_user, login, monkeypatch):
    make_user("mia.member", "member")
    headers = login("mia.member")
    monkeypatch.setenv("APP_ENV", "demo")

    request = submit(client, headers, "viewer").json()["request"]

    assert request["is_seed"] is True
