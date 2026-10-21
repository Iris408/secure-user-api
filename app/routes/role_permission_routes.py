from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.audit import AuditEventType, AuditOutcome, record_event
from app.auth import CurrentUser, deny_access, require_permission
from app.database import get_db
from app.models.role_permission_model import RolePermissionGrant
from app.permissions import (
    EDITABLE_ROLES,
    MATRIX_PERMISSIONS,
    Permission,
    Role,
    is_configurable,
    lock_reason,
    normalize_role,
)
from app.policy import (
    effective_grants,
    load_grants,
    permissions_from,
    policy_version,
)


# =========================================
# EN: Role permission policy (Admin only)
# JP: ロール権限ポリシー（管理者のみ）
# KR: 역할 권한 정책 (관리자 전용)
# =========================================
#
# Admins read and change the configurable cells of the permission matrix.
# Fixed cells — the Admin column, Admin-only permissions (users:manage,
# audit:read, roles:manage) and Viewer / Auditor's read-only limits — are
# reported with a lock reason and can't be changed. An update replaces the
# whole matrix in one transaction and is audited per changed role.

router = APIRouter()

LOCK_MESSAGES = {
    "admin_full_access": "Admin always has every permission",
    "admin_only": "only Admin can have this permission",
    "audit_admin_only": "the audit log is limited to Admin",
    "viewer_read_only": "Viewer / Auditor is read-only",
    "member_submit_required": "Members can always submit access requests",
    "fixed": "this permission can't be changed for this role",
}

STALE_DETAIL = "Role permissions were changed by someone else. Reload and try again."


def require_role_admin(
    request: Request,
    current_user: CurrentUser = Depends(require_permission(Permission.ROLES_MANAGE)),
    db: Session = Depends(get_db),
) -> CurrentUser:
    # roles:manage is fixed to Admin; the role check (from the database, never
    # the token) is a second, independent safeguard.
    if normalize_role(current_user.role) != Role.ADMIN:
        deny_access(db, request, current_user, Permission.ROLES_MANAGE, reason="admin_only")

    return current_user


def matrix_permissions(role: Role, grants: dict) -> list:
    """The matrix permissions a role has, as sorted codes."""
    resolved = permissions_from(role, grants)
    return sorted(permission.value for permission in MATRIX_PERMISSIONS if permission in resolved)


def matrix_response(db: Session) -> dict:
    grants = load_grants(db)
    effective = effective_grants(grants)

    rows = []
    for permission in MATRIX_PERMISSIONS:
        cells = {}
        for role in Role:
            reason = lock_reason(role, permission)
            granted = (
                effective[(role, permission)]
                if reason is None
                else permission in permissions_from(role, grants)
            )
            cells[role.value] = {
                "granted": granted,
                "editable": reason is None,
                "lock_reason": reason,
            }
        rows.append({"permission": permission.value, "roles": cells})

    latest = (
        db.query(RolePermissionGrant)
        .filter(RolePermissionGrant.updated_at.isnot(None))
        .order_by(RolePermissionGrant.updated_at.desc())
        .first()
    )

    return {
        "roles": [role.value for role in Role],
        "permissions": rows,
        "version": policy_version(grants),
        "updated_at": latest.updated_at.isoformat() if latest else None,
        "updated_by": (
            {"id": latest.updated_by_id, "username": latest.updated_by_username}
            if latest
            else None
        ),
    }


class RolePermissionUpdate(BaseModel):
    # From GET /role-permissions; an update based on an older matrix is refused.
    version: str = Field(min_length=1, max_length=64)
    # The complete set of matrix permissions for every editable role.
    grants: Dict[str, List[str]] = Field(max_length=len(Role))


def invalid(detail: str):
    raise HTTPException(status_code=422, detail=detail)


def desired_cells(update: RolePermissionUpdate) -> dict:
    """Validate the requested matrix; return {(role, permission): granted}."""

    if Role.ADMIN.value in {key.strip().lower() for key in update.grants}:
        invalid("Admin permissions can't be changed")

    requested = {}
    for key, codes in update.grants.items():
        try:
            role = Role(key)
        except ValueError:
            invalid(f"Unknown role: {key}")

        permissions = set()
        for code in codes:
            try:
                permission = Permission(code)
            except ValueError:
                invalid(f"Unknown permission: {code}")
            if permission not in MATRIX_PERMISSIONS:
                invalid(f"{code} can't be configured")
            permissions.add(permission)
        requested[role] = permissions

    missing = [role.value for role in EDITABLE_ROLES if role not in requested]
    if missing:
        invalid(f"Include every role: {', '.join(missing)} missing")

    cells = {}
    for role in EDITABLE_ROLES:
        for permission in MATRIX_PERMISSIONS:
            wanted = permission in requested[role]
            reason = lock_reason(role, permission)

            if reason is None:
                cells[(role, permission)] = wanted
                continue

            # Fixed cells must be sent exactly as they are.
            fixed = permission in permissions_from(role, {})
            if wanted != fixed:
                invalid(
                    f"{permission.value} can't be "
                    f"{'granted to' if wanted else 'removed from'} {role.value}: "
                    f"{LOCK_MESSAGES[reason]}"
                )

    return cells


@router.get("/role-permissions")
def get_role_permissions(
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(require_role_admin),
):
    return matrix_response(db)


@router.put("/role-permissions")
def update_role_permissions(
    update: RolePermissionUpdate,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(require_role_admin),
):
    cells = desired_cells(update)

    # Lock every stored cell so concurrent updates are applied one at a time
    # and the version check below sees the latest state.
    rows = {
        (row.role, row.permission): row
        for row in db.query(RolePermissionGrant).with_for_update().all()
    }
    before = load_grants(db)

    if update.version != policy_version(before):
        raise HTTPException(status_code=409, detail=STALE_DETAIL)

    after = effective_grants(before)
    after.update(cells)

    now = datetime.now(timezone.utc)
    for (role, permission), granted in cells.items():
        if not is_configurable(role, permission):
            continue
        row = rows.get((role.value, permission.value))
        if row is None:
            row = RolePermissionGrant(role=role.value, permission=permission.value)
            db.add(row)
        elif bool(row.granted) == granted:
            continue
        row.granted = granted
        row.updated_at = now
        row.updated_by_id = current_user.id
        row.updated_by_username = current_user.username

    for role in EDITABLE_ROLES:
        from_permissions = matrix_permissions(role, before)
        to_permissions = matrix_permissions(role, after)
        if from_permissions == to_permissions:
            continue

        record_event(
            db, AuditEventType.ROLE_PERMISSIONS_CHANGED, AuditOutcome.SUCCESS,
            actor=current_user,
            target=SimpleNamespace(audit_target_type="role", id=None, username=role.value),
            details={
                "role": role.value,
                "from_permissions": ",".join(from_permissions),
                "to_permissions": ",".join(to_permissions),
            },
        )

    # Every cell and its audit events are saved together, or not at all.
    db.commit()

    return matrix_response(db)

