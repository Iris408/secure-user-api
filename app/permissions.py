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

    # Access requests
    ACCESS_REQUESTS_SUBMIT = "access_requests:submit"
    ACCESS_REQUESTS_REVIEW = "access_requests:review"

    # The organisation Activity feed (GET /activity)
    ACTIVITY_READ = "activity:read"

    # Audit log, the permission policy and organisation settings (Admin only,
    # never editable)
    AUDIT_READ = "audit:read"
    ROLES_MANAGE = "roles:manage"
    SETTINGS_MANAGE = "settings:manage"


# =========================================
# EN: Default policy and what may be configured
# JP: 既定ポリシーと変更可能な範囲
# KR: 기본 정책과 변경 가능한 범위
# =========================================
#
# The effective policy is resolved in app/policy.py: fixed cells come from
# DEFAULT_ROLE_PERMISSIONS, configurable cells from the role_permission_grants
# table (falling back to the default when a row is missing).

DEFAULT_ROLE_PERMISSIONS = {
    # Admin always has every permission (an invariant, not a setting).
    Role.ADMIN: frozenset(Permission),
    Role.MANAGER: frozenset({
        Permission.ACCESS_REQUESTS_SUBMIT,
        Permission.ACCESS_REQUESTS_REVIEW,
        Permission.ACTIVITY_READ,
    }),
    Role.MEMBER: frozenset({
        Permission.ACCESS_REQUESTS_SUBMIT,
    }),
    # Read-only. audit:read is Admin-only by policy, so Viewer / Auditor no
    # longer lists it (the audit log has always required the Admin role).
    Role.VIEWER: frozenset({
        Permission.ACTIVITY_READ,
    }),
}

# Permissions shown in the Roles matrix, in display order.
MATRIX_PERMISSIONS = (
    Permission.USERS_READ,
    Permission.USERS_MANAGE,
    Permission.ACCESS_REQUESTS_SUBMIT,
    Permission.ACCESS_REQUESTS_REVIEW,
    Permission.ACTIVITY_READ,
    Permission.AUDIT_READ,
    Permission.ROLES_MANAGE,
    Permission.SETTINGS_MANAGE,
)

# The only cells an Admin may change. Everything else in the matrix is fixed.
CONFIGURABLE = {
    Permission.USERS_READ: frozenset({Role.MANAGER, Role.MEMBER, Role.VIEWER}),
    Permission.ACCESS_REQUESTS_SUBMIT: frozenset({Role.MANAGER}),
    Permission.ACCESS_REQUESTS_REVIEW: frozenset({Role.MANAGER, Role.MEMBER}),
    # Reading the feed is read-only, so Viewer / Auditor may hold it.
    Permission.ACTIVITY_READ: frozenset({Role.MANAGER, Role.MEMBER, Role.VIEWER}),
}

EDITABLE_ROLES = (Role.MANAGER, Role.MEMBER, Role.VIEWER)


def is_configurable(role: Role, permission: Permission) -> bool:
    return role in CONFIGURABLE.get(permission, frozenset())


def lock_reason(role: Role, permission: Permission):
    """Why a matrix cell can't be changed, or None if it can."""
    if role is Role.ADMIN:
        return "admin_full_access"
    if is_configurable(role, permission):
        return None
    if permission is Permission.AUDIT_READ:
        return "audit_admin_only"
    if permission in (Permission.USERS_MANAGE, Permission.ROLES_MANAGE, Permission.SETTINGS_MANAGE):
        return "admin_only"
    if role is Role.VIEWER:
        return "viewer_read_only"
    if role is Role.MEMBER and permission is Permission.ACCESS_REQUESTS_SUBMIT:
        return "member_submit_required"
    return "fixed"


def default_permissions_for(role) -> list:
    """Sorted default permission strings for a (possibly legacy) role value."""
    return sorted(p.value for p in DEFAULT_ROLE_PERMISSIONS[normalize_role(role)])


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
