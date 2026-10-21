from datetime import datetime, timezone
from enum import Enum

from sqlalchemy.orm import Session

from app.models.audit_model import AuditEvent
from app.permissions import normalize_role


# =========================================
# EN: Audit event recording
# JP: 監査イベントの記録
# KR: 감사 이벤트 기록
# =========================================
#
# A deliberately small, defined set of security and administrative events.
# Routine reads are not recorded. Records are written in the same transaction
# as the change they describe, so a change and its audit record are committed
# together (or not at all).
#
# Never pass credentials here: details are filtered through an allow-list of
# keys and simple values, so passwords, temporary passwords, tokens and keys
# have no field to land in.


class AuditEventType(str, Enum):
    SIGN_IN = "auth.sign_in"
    PASSWORD_CHANGED = "auth.password_changed"
    DEMO_SESSION = "auth.demo_session"
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    ROLE_CHANGED = "user.role_changed"
    USER_DEACTIVATED = "user.deactivated"
    USER_REACTIVATED = "user.reactivated"
    USER_DELETED = "user.deleted"
    ACCESS_DENIED = "access.denied"
    ACCESS_REQUEST_SUBMITTED = "access_request.submitted"
    ACCESS_REQUEST_APPROVED = "access_request.approved"
    ACCESS_REQUEST_DECLINED = "access_request.declined"
    ROLE_PERMISSIONS_CHANGED = "role.permissions_changed"
    SETTINGS_CHANGED = "settings.changed"


class AuditOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    # Refused by a permission check or a safeguard
    DENIED = "denied"


# Keys that may appear in `details`. Anything else is dropped.
SAFE_DETAIL_KEYS = {
    "reason",
    "method",
    "role",
    "from_role",
    "to_role",
    "from_username",
    "to_username",
    "password_generated",
    "permission",
    "action",
    # Access requests: identifiers and role codes only. The free-text reason
    # and decision note stay in the access_requests table, never here.
    "request_id",
    "requested_role",
    # Role permission changes: comma-separated permission codes, e.g.
    # "access_requests:review,users:read" (or "" for none).
    "from_permissions",
    "to_permissions",
    # Organisation settings: which setting, and display-safe old/new values.
    "setting",
    "from_value",
    "to_value",
}

# Defence in depth: never keep a key that looks like a credential, even if
# someone adds it to the allow-list by mistake.
SENSITIVE_KEY_FRAGMENTS = ("password", "token", "secret", "key", "jwt", "credential")
ALLOWED_SENSITIVE_LOOKING_KEYS = {"password_generated"}

MAX_DETAIL_LENGTH = 200


def safe_details(details) -> dict:
    """Keep only allow-listed keys with short, simple values."""

    clean = {}

    for key, value in (details or {}).items():
        if key not in SAFE_DETAIL_KEYS:
            continue

        lowered = key.lower()
        if key not in ALLOWED_SENSITIVE_LOOKING_KEYS and any(
            fragment in lowered for fragment in SENSITIVE_KEY_FRAGMENTS
        ):
            continue

        if isinstance(value, Enum):
            value = value.value

        if value is None or isinstance(value, (bool, int, float)):
            clean[key] = value
        elif isinstance(value, str):
            clean[key] = value[:MAX_DETAIL_LENGTH]

    return clean


def record_event(
    db: Session,
    event_type: AuditEventType,
    outcome: AuditOutcome,
    *,
    actor=None,
    target=None,
    details=None,
) -> AuditEvent:
    """
    Add an audit event to the current transaction. The caller commits, so the
    record is saved together with the change it describes.

    `actor` and `target` may be a User row or the authenticated CurrentUser;
    only their id, username and role are copied.
    """

    event = AuditEvent(
        occurred_at=datetime.now(timezone.utc),
        event_type=AuditEventType(event_type).value,
        outcome=AuditOutcome(outcome).value,
        details=safe_details(details),
    )

    if actor is not None:
        event.actor_id = actor.id
        event.actor_username = actor.username
        event.actor_role = normalize_role(actor.role).value

    if target is not None:
        # A User/CurrentUser by default; a role target sets `audit_target_type`.
        event.target_type = getattr(target, "audit_target_type", "user")
        event.target_id = target.id
        event.target_username = target.username

    db.add(event)
    return event


def event_to_dict(event: AuditEvent) -> dict:
    occurred_at = event.occurred_at

    if occurred_at is not None and occurred_at.tzinfo is None:
        occurred_at = occurred_at.replace(tzinfo=timezone.utc)

    return {
        "id": event.id,
        "occurred_at": occurred_at.isoformat() if occurred_at else None,
        "event_type": event.event_type,
        "outcome": event.outcome,
        "actor": (
            {
                "id": event.actor_id,
                "username": event.actor_username,
                "role": event.actor_role,
            }
            if event.actor_id is not None or event.actor_username
            else None
        ),
        "target": (
            {
                "type": event.target_type,
                "id": event.target_id,
                "username": event.target_username,
            }
            if event.target_type
            else None
        ),
        "details": safe_details(event.details),
    }
