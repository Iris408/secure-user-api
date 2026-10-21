import hashlib

from sqlalchemy.orm import Session

from app.models.role_permission_model import RolePermissionGrant
from app.permissions import (
    CONFIGURABLE,
    DEFAULT_ROLE_PERMISSIONS,
    EDITABLE_ROLES,
    MATRIX_PERMISSIONS,
    Permission,
    Role,
    is_configurable,
    normalize_role,
)


# =========================================
# EN: Effective permission policy
# JP: 有効な権限ポリシー
# KR: 유효 권한 정책
# =========================================
#
# The single place permissions are resolved. Called on every authenticated
# request with the role read from the database, so a policy change applies to
# existing sessions immediately and token claims are never trusted.


def configurable_cells():
    """Every (role, permission) pair an Admin may change, in a stable order."""
    return [
        (role, permission)
        for permission in MATRIX_PERMISSIONS
        for role in EDITABLE_ROLES
        if is_configurable(role, permission)
    ]


def default_granted(role: Role, permission: Permission) -> bool:
    return permission in DEFAULT_ROLE_PERMISSIONS[role]


def load_grants(db: Session, role: Role = None, *, for_update: bool = False) -> dict:
    """Stored configurable cells as {(role, permission): granted}."""
    query = db.query(RolePermissionGrant)
    if role is not None:
        query = query.filter(RolePermissionGrant.role == role.value)
    if for_update:
        query = query.with_for_update()

    grants = {}
    for row in query.all():
        try:
            cell = (Role(row.role), Permission(row.permission))
        except ValueError:
            continue
        # Rows for cells that are no longer configurable are ignored.
        if is_configurable(*cell):
            grants[cell] = bool(row.granted)
    return grants


def effective_grants(grants: dict) -> dict:
    """Every configurable cell, with defaults filled in for missing rows."""
    return {
        cell: grants.get(cell, default_granted(*cell))
        for cell in configurable_cells()
    }


def permissions_from(role: Role, grants: dict) -> frozenset:
    if role is Role.ADMIN:
        return frozenset(Permission)

    fixed = {
        permission
        for permission in DEFAULT_ROLE_PERMISSIONS[role]
        if not is_configurable(role, permission)
    }
    configured = {
        permission
        for permission, roles in CONFIGURABLE.items()
        if role in roles and grants.get((role, permission), default_granted(role, permission))
    }
    return frozenset(fixed | configured)


def resolve_permissions(db: Session, role) -> frozenset:
    """The current permissions for a role (any stored value)."""
    role = normalize_role(role)
    if role is Role.ADMIN:
        return frozenset(Permission)
    return permissions_from(role, load_grants(db, role))


def policy_version(grants: dict) -> str:
    """Fingerprint of the configurable cells, used to reject stale updates."""
    state = ";".join(
        f"{role.value}:{permission.value}={int(granted)}"
        for (role, permission), granted in sorted(
            effective_grants(grants).items(), key=lambda item: (item[0][0].value, item[0][1].value)
        )
    )
    return hashlib.sha256(state.encode()).hexdigest()[:16]
