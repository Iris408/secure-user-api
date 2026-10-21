from sqlalchemy import Boolean, Column, DateTime, Integer, String

from app.database import Base


# =========================================
# EN: Configurable role permissions
# JP: 変更可能なロール権限
# KR: 변경 가능한 역할 권한
# =========================================
#
# One row per configurable (role, permission) cell — see CONFIGURABLE in
# app/permissions.py. Fixed cells (the Admin column, Admin-only permissions,
# Viewer / Auditor's read-only limits) are never stored, so they can't be
# changed here. Rows are created with today's defaults at start-up
# (app/migrations.py) and only ever updated by PUT /role-permissions.

class RolePermissionGrant(Base):

    __tablename__ = "role_permission_grants"

    role = Column(String(16), primary_key=True)
    permission = Column(String(64), primary_key=True)
    granted = Column(Boolean, nullable=False)

    # Who last changed the cell (snapshot; null for start-up defaults)
    updated_at = Column(DateTime(timezone=True), nullable=True)
    updated_by_id = Column(Integer, nullable=True)
    updated_by_username = Column(String, nullable=True)
