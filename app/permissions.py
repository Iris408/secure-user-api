from enum import Enum


# =========================================
# EN: Roles and permissions (single source of truth)
# JP: ロールと権限（唯一の定義元）
# KR: 역할과 권한 (단일 기준)
# =========================================


class Role(str, Enum):
    ADMIN = "admin"
    MANAGER = "manager"
    MEMBER = "member"
    VIEWER = "viewer"  # shown as "Viewer / Auditor"


class Permission(str, Enum):
    # User directory and lifecycle
    USERS_READ = "users:read"
    USERS_MANAGE = "users:manage"

    # Future phases: declared now so role boundaries are fixed and testable
    ACCESS_REQUESTS_SUBMIT = "access_requests:submit"
    ACCESS_REQUESTS_REVIEW = "access_requests:review"
    ACTIVITY_READ_TEAM = "activity:read_team"
    ACTIVITY_READ_ALL = "activity:read_all"
    AUDIT_READ = "audit:read"


ROLE_PERMISSIONS = {
    # Admin manages users and roles and can see everything.
    Role.ADMIN: frozenset(Permission),
    # Manager handles access requests and sees their team's activity.
    Role.MANAGER: frozenset({
        Permission.ACCESS_REQUESTS_SUBMIT,
        Permission.ACCESS_REQUESTS_REVIEW,
        Permission.ACTIVITY_READ_TEAM,
    }),
    # Member uses the service and can ask for more access.
    Role.MEMBER: frozenset({
        Permission.ACCESS_REQUESTS_SUBMIT,
    }),
    # Viewer / Auditor reads activity and audit records; never changes data.
    Role.VIEWER: frozenset({
        Permission.ACTIVITY_READ_ALL,
        Permission.AUDIT_READ,
    }),
}

# Values accepted on input that map onto a canonical role. "user" is the
# original standard-account value and keeps the same (non-admin) rights.
LEGACY_ROLE_ALIASES = {
    "user": Role.MEMBER,
    "auditor": Role.VIEWER,
}


def normalize_role(value) -> Role:
    """
    Map a stored role string onto one of the four roles.

    Existing rows hold "admin", "Admin" or "user". Matching is
    case-insensitive and anything unrecognised becomes Member, which grants
    the least privilege any signed-in user had before — so no account is
    locked out or silently promoted.
    """
    key = (value or "").strip().lower()

    try:
        return Role(key)
    except ValueError:
        return LEGACY_ROLE_ALIASES.get(key, Role.MEMBER)


def parse_role(value: str) -> Role:
    """Strict variant for request input: unknown roles are rejected."""
    key = (value or "").strip().lower()

    if key in Role._value2member_map_:
        return Role(key)

    if key in LEGACY_ROLE_ALIASES:
        return LEGACY_ROLE_ALIASES[key]

    allowed = ", ".join(role.value for role in Role)
    raise ValueError(f"Role must be one of: {allowed}")


def permissions_for(role) -> list:
    """Sorted permission strings for a (possibly legacy) role value."""
    return sorted(
        permission.value
        for permission in ROLE_PERMISSIONS[normalize_role(role)]
    )


def has_permission(role, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS[normalize_role(role)]
