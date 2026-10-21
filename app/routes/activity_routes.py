from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.audit import AuditEventType, AuditOutcome, safe_details
from app.auth import CurrentUser, require_permission
from app.database import get_db
from app.models.audit_model import AuditEvent
from app.permissions import Permission


# =========================================
# EN: Organisation activity feed
# JP: 組織のアクティビティフィード
# KR: 조직 활동 피드
# =========================================
#
# A scannable, read-only view of the events the API already records in the
# audit log (sign-ins, denials, user, role, request and permission changes).
# It is NOT the audit log: it needs activity:read rather than the Admin-only
# audit:read, and returns a smaller projection — no account or request IDs,
# no route templates, no sign-in method — so it can be shared more widely.
# Nothing is recorded here; routine reads are never events.

router = APIRouter()

MAX_PAGE_SIZE = 100

# Every recorded event type is a meaningful security or access event, so all
# of them appear. A new event type must be added here deliberately.
ACTIVITY_EVENT_TYPES = frozenset({
    AuditEventType.SIGN_IN,
    AuditEventType.PASSWORD_CHANGED,
    AuditEventType.DEMO_SESSION,
    AuditEventType.USER_CREATED,
    AuditEventType.USER_UPDATED,
    AuditEventType.ROLE_CHANGED,
    AuditEventType.USER_DEACTIVATED,
    AuditEventType.USER_REACTIVATED,
    AuditEventType.USER_DELETED,
    AuditEventType.ACCESS_DENIED,
    AuditEventType.ACCESS_REQUEST_SUBMITTED,
    AuditEventType.ACCESS_REQUEST_APPROVED,
    AuditEventType.ACCESS_REQUEST_DECLINED,
    AuditEventType.ROLE_PERMISSIONS_CHANGED,
    AuditEventType.SETTINGS_CHANGED,
})

# Detail fields shown in the feed: short codes and role/permission names.
# Left out: request_id, action (route template), method, password_generated.
ACTIVITY_DETAIL_KEYS = frozenset({
    "reason",
    "role",
    "from_role",
    "to_role",
    "requested_role",
    "from_username",
    "to_username",
    "permission",
    "from_permissions",
    "to_permissions",
    "setting",
    "from_value",
    "to_value",
})


def escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def activity_to_dict(event: AuditEvent) -> dict:
    occurred_at = event.occurred_at
    if occurred_at is not None and occurred_at.tzinfo is None:
        occurred_at = occurred_at.replace(tzinfo=timezone.utc)
    details = safe_details(event.details)

    return {
        "id": event.id,
        "occurred_at": occurred_at.isoformat() if occurred_at else None,
        "event_type": event.event_type,
        "outcome": event.outcome,
        "actor": (
            {"username": event.actor_username, "role": event.actor_role}
            if event.actor_username
            else None
        ),
        "target": (
            {"type": event.target_type, "username": event.target_username}
            if event.target_type and event.target_username
            else None
        ),
        "details": {key: value for key, value in details.items() if key in ACTIVITY_DETAIL_KEYS},
    }


@router.get("/activity")
def list_activity(
    event_type: Optional[AuditEventType] = None,
    outcome: Optional[AuditOutcome] = None,
    q: Optional[str] = Query(None, max_length=100, description="Actor or target username contains"),
    since: Optional[datetime] = Query(None, description="ISO 8601, inclusive"),
    until: Optional[datetime] = Query(None, description="ISO 8601, exclusive"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=MAX_PAGE_SIZE),
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(require_permission(Permission.ACTIVITY_READ)),
):
    if since and until and since >= until:
        raise HTTPException(status_code=400, detail="'since' must be earlier than 'until'")

    if event_type and event_type not in ACTIVITY_EVENT_TYPES:
        raise HTTPException(status_code=422, detail="This event type isn't part of the activity feed")

    query = db.query(AuditEvent).filter(
        AuditEvent.event_type.in_([event.value for event in ACTIVITY_EVENT_TYPES])
    )

    if event_type:
        query = query.filter(AuditEvent.event_type == event_type.value)

    if outcome:
        query = query.filter(AuditEvent.outcome == outcome.value)

    if q and q.strip():
        pattern = f"%{escape_like(q.strip())}%"
        query = query.filter(or_(
            AuditEvent.actor_username.ilike(pattern, escape="\\"),
            AuditEvent.target_username.ilike(pattern, escape="\\"),
        ))

    if since:
        query = query.filter(AuditEvent.occurred_at >= since)

    if until:
        query = query.filter(AuditEvent.occurred_at < until)

    total = query.count()
    events = (
        query.order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return {
        "events": [activity_to_dict(event) for event in events],
        "total": total,
        "page": page,
        "page_size": page_size,
    }
