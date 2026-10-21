from dataclasses import dataclass
from functools import lru_cache
from zoneinfo import available_timezones

from sqlalchemy.orm import Session

from app.models.settings_model import OrganisationSettings
from app.permissions import Role


# =========================================
# EN: Organisation settings: defaults and reading
# JP: 組織の設定：既定値と読み込み
# KR: 조직 설정: 기본값과 읽기
# =========================================
#
# Every setting here has a real effect:
#   organisation_name       shown to signed-in users (GET /organisation)
#   timezone                how the interface shows dates and times
#   access_requests_enabled POST /access-requests refuses new requests when off
#   requestable_roles       POST /access-requests refuses other roles
#   session_minutes         lifetime of newly issued sign-in tokens
# The defaults match how AccessHub behaved before settings existed.

SETTINGS_ID = 1

# Roles that may ever be requested. Admin is never one of them.
REQUESTABLE_ROLE_CHOICES = (Role.MANAGER, Role.MEMBER, Role.VIEWER)

ORGANISATION_NAME_MAX = 80
SESSION_MINUTES_MIN = 15
SESSION_MINUTES_MAX = 720


@dataclass(frozen=True)
class SettingsValues:
    organisation_name: str | None = None
    timezone: str | None = None
    access_requests_enabled: bool = True
    requestable_roles: tuple = tuple(role.value for role in REQUESTABLE_ROLE_CHOICES)
    session_minutes: int = 30
    revision: int = 0


DEFAULTS = SettingsValues()


@lru_cache(maxsize=1)
def known_timezones() -> frozenset:
    """IANA timezone names from the system (or tzdata) database."""
    return frozenset(available_timezones())


def parse_roles(value: str | None) -> tuple:
    """Stored comma list → canonical, ordered tuple of requestable roles."""
    stored = {part.strip().lower() for part in (value or "").split(",")}
    return tuple(role.value for role in REQUESTABLE_ROLE_CHOICES if role.value in stored)


def join_roles(roles) -> str:
    return ",".join(roles)


def values_from(row: OrganisationSettings | None) -> SettingsValues:
    if row is None:
        return DEFAULTS

    minutes = row.session_minutes
    if not isinstance(minutes, int) or not SESSION_MINUTES_MIN <= minutes <= SESSION_MINUTES_MAX:
        minutes = DEFAULTS.session_minutes

    timezone = row.timezone if row.timezone in known_timezones() else None

    return SettingsValues(
        organisation_name=row.organisation_name or None,
        timezone=timezone,
        access_requests_enabled=bool(row.access_requests_enabled),
        requestable_roles=parse_roles(row.requestable_roles),
        session_minutes=minutes,
        revision=row.revision or 0,
    )


def load_settings(db: Session) -> SettingsValues:
    """The saved settings, or the defaults if the row doesn't exist yet."""
    return values_from(db.get(OrganisationSettings, SETTINGS_ID))
