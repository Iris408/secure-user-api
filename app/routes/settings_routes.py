from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt
from sqlalchemy.orm import Session

from app.audit import AuditEventType, AuditOutcome, record_event
from app.auth import CurrentUser, deny_access, get_active_user, require_permission
from app.database import get_db
from app.models.settings_model import OrganisationSettings
from app.permissions import Permission, Role, normalize_role
from app.settings import (
    DEFAULTS,
    ORGANISATION_NAME_MAX,
    REQUESTABLE_ROLE_CHOICES,
    SESSION_MINUTES_MAX,
    SESSION_MINUTES_MIN,
    SETTINGS_ID,
    SettingsValues,
    join_roles,
    known_timezones,
    load_settings,
    values_from,
)


# =========================================
# EN: Organisation settings (Admin only)
# JP: 組織の設定（管理者のみ）
# KR: 조직 설정 (관리자 전용)
# =========================================
#
# GET/PUT /settings are for Admins (settings:manage, fixed to Admin, plus a
# role check). GET /organisation gives every signed-in user the parts the
# interface needs: the name, timezone and access request policy — never the
# session length or who changed what.

router = APIRouter()

STALE_DETAIL = "Settings were changed by someone else. Reload and try again."


def require_settings_admin(
    request: Request,
    current_user: CurrentUser = Depends(require_permission(Permission.SETTINGS_MANAGE)),
    db: Session = Depends(get_db),
) -> CurrentUser:
    # settings:manage is fixed to Admin; the role check (from the database,
    # never the token) is a second, independent safeguard.
    if normalize_role(current_user.role) != Role.ADMIN:
        deny_access(db, request, current_user, Permission.SETTINGS_MANAGE, reason="admin_only")
    return current_user


def settings_response(db: Session) -> dict:
    row = db.get(OrganisationSettings, SETTINGS_ID)
    values = values_from(row)

    return {
        "organisation_name": values.organisation_name,
        "timezone": values.timezone,
        "access_requests_enabled": values.access_requests_enabled,
        "requestable_roles": list(values.requestable_roles),
        "session_minutes": values.session_minutes,
        "revision": values.revision,
        "updated_at": row.updated_at.isoformat() if row and row.updated_at else None,
        "updated_by": (
            {"id": row.updated_by_id, "username": row.updated_by_username}
            if row and row.updated_at
            else None
        ),
        "limits": {
            "organisation_name_max": ORGANISATION_NAME_MAX,
            "session_minutes_min": SESSION_MINUTES_MIN,
            "session_minutes_max": SESSION_MINUTES_MAX,
            "requestable_roles": [role.value for role in REQUESTABLE_ROLE_CHOICES],
        },
    }


class SettingsUpdate(BaseModel):
    # Unknown fields are refused rather than silently ignored.
    model_config = ConfigDict(extra="forbid")

    # From GET /settings; an update based on an older copy is refused (409).
    revision: StrictInt
    organisation_name: Optional[str] = Field(max_length=200)
    timezone: Optional[str] = Field(max_length=64)
    access_requests_enabled: StrictBool
    requestable_roles: List[str] = Field(max_length=10)
    session_minutes: StrictInt


def invalid(detail: str):
    raise HTTPException(status_code=422, detail=detail)


def validated(update: SettingsUpdate) -> SettingsValues:
    """Check every field; return the canonical values to store."""

    name = (update.organisation_name or "").strip()
    if len(name) > ORGANISATION_NAME_MAX:
        invalid(f"Organisation name must be {ORGANISATION_NAME_MAX} characters or fewer")
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        invalid("Organisation name can't contain control characters")

    zone = (update.timezone or "").strip()
    if zone and zone not in known_timezones():
        invalid(f"Unknown timezone: {zone}")

    allowed = {role.value for role in REQUESTABLE_ROLE_CHOICES}
    requested = set()
    for value in update.requestable_roles:
        key = value.strip().lower()
        if key == Role.ADMIN.value:
            invalid("Admin can never be requested")
        if key not in allowed:
            invalid(f"Unknown role: {value}")
        requested.add(key)
    roles = tuple(role.value for role in REQUESTABLE_ROLE_CHOICES if role.value in requested)

    if update.access_requests_enabled and not roles:
        invalid("Choose at least one role that can be requested, or turn access requests off")

    if not SESSION_MINUTES_MIN <= update.session_minutes <= SESSION_MINUTES_MAX:
        invalid(
            f"Session length must be between {SESSION_MINUTES_MIN} and "
            f"{SESSION_MINUTES_MAX} minutes"
        )

    return SettingsValues(
        organisation_name=name or None,
        timezone=zone or None,
        access_requests_enabled=update.access_requests_enabled,
        requestable_roles=roles,
        session_minutes=update.session_minutes,
    )


def display(field: str, values: SettingsValues) -> str:
    """A setting's value as short, display-safe audit text."""
    value = getattr(values, field)
    if field == "requestable_roles":
        return join_roles(value)
    if isinstance(value, bool):
        return "on" if value else "off"
    return "" if value is None else str(value)


AUDITED_FIELDS = (
    "organisation_name",
    "timezone",
    "access_requests_enabled",
    "requestable_roles",
    "session_minutes",
)


@router.get("/settings")
def get_settings(
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(require_settings_admin),
):
    return settings_response(db)


@router.put("/settings")
def update_settings(
    update: SettingsUpdate,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(require_settings_admin),
):
    after = validated(update)

    # Lock the row so concurrent saves apply one at a time and the revision
    # check sees the latest state.
    row = (
        db.query(OrganisationSettings)
        .filter(OrganisationSettings.id == SETTINGS_ID)
        .with_for_update()
        .first()
    )
    if row is None:
        row = OrganisationSettings(
            id=SETTINGS_ID,
            access_requests_enabled=DEFAULTS.access_requests_enabled,
            requestable_roles=join_roles(DEFAULTS.requestable_roles),
            session_minutes=DEFAULTS.session_minutes,
            revision=0,
        )
        db.add(row)

    before = values_from(row)
    if update.revision != before.revision:
        raise HTTPException(status_code=409, detail=STALE_DETAIL)

    changed = [field for field in AUDITED_FIELDS if display(field, before) != display(field, after)]
    if not changed:
        return settings_response(db)

    row.organisation_name = after.organisation_name
    row.timezone = after.timezone
    row.access_requests_enabled = after.access_requests_enabled
    row.requestable_roles = join_roles(after.requestable_roles)
    row.session_minutes = after.session_minutes
    row.revision = before.revision + 1
    row.updated_at = datetime.now(timezone.utc)
    row.updated_by_id = current_user.id
    row.updated_by_username = current_user.username

    for field in changed:
        record_event(
            db, AuditEventType.SETTINGS_CHANGED, AuditOutcome.SUCCESS,
            actor=current_user,
            details={
                "setting": field,
                "from_value": display(field, before),
                "to_value": display(field, after),
            },
        )

    # The settings and their audit events are saved together, or not at all.
    db.commit()

    return settings_response(db)


@router.get("/organisation")
def get_organisation(
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_active_user),
):
    values = load_settings(db)
    return {
        "organisation_name": values.organisation_name,
        "timezone": values.timezone,
        "access_requests": {
            "enabled": values.access_requests_enabled,
            "requestable_roles": list(values.requestable_roles),
        },
    }
