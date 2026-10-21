from sqlalchemy import Boolean, CheckConstraint, Column, DateTime, Integer, String

from app.database import Base


# =========================================
# EN: Organisation settings (one row)
# JP: 組織の設定（1 行）
# KR: 조직 설정 (한 행)
# =========================================
#
# A single row (id = 1), created with defaults at start-up
# (app/migrations.py) and only changed by PUT /settings. `revision` increases
# with every change so an update based on an older copy can be refused.

class OrganisationSettings(Base):

    __tablename__ = "organisation_settings"
    __table_args__ = (CheckConstraint("id = 1", name="ck_organisation_settings_single_row"),)

    id = Column(Integer, primary_key=True)

    # Shown to signed-in users; null = no name shown
    organisation_name = Column(String(80), nullable=True)
    # IANA name such as "Europe/London"; null = each viewer's local time
    timezone = Column(String(64), nullable=True)

    access_requests_enabled = Column(Boolean, nullable=False, default=True)
    # Comma-separated non-Admin roles, e.g. "manager,member,viewer"
    requestable_roles = Column(String(64), nullable=False)

    # Lifetime of newly issued sign-in tokens
    session_minutes = Column(Integer, nullable=False)

    revision = Column(Integer, nullable=False, default=0)
    updated_at = Column(DateTime(timezone=True), nullable=True)
    updated_by_id = Column(Integer, nullable=True)
    updated_by_username = Column(String, nullable=True)
