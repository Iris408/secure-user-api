from sqlalchemy import Boolean, Column, DateTime, Index, Integer, String, Text, false, func, text

from app.database import Base


# =========================================
# EN: Access requests (role change requests)
# JP: アクセス申請（ロール変更申請）
# KR: 접근 요청 (역할 변경 요청)
# =========================================
#
# Requester and reviewer are stored as snapshots (id, username, role at the
# time) rather than foreign keys, so the history stays understandable after a
# user is renamed or deleted. The submitted role and reason never change after
# submission; a decision only fills in the decision columns.

class AccessRequestStatus:
    PENDING = "pending"
    APPROVED = "approved"
    DECLINED = "declined"

    ALL = (PENDING, APPROVED, DECLINED)


class AccessRequest(Base):

    __tablename__ = "access_requests"

    id = Column(Integer, primary_key=True)

    submitted_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )

    requester_id = Column(Integer, nullable=False, index=True)
    requester_username = Column(String, nullable=False)
    requester_role = Column(String, nullable=False)  # role when submitted

    requested_role = Column(String(16), nullable=False, index=True)
    reason = Column(Text, nullable=False)

    status = Column(
        String(16), nullable=False, default=AccessRequestStatus.PENDING, index=True
    )

    reviewer_id = Column(Integer, nullable=True)
    reviewer_username = Column(String, nullable=True)
    reviewer_role = Column(String, nullable=True)
    decided_at = Column(DateTime(timezone=True), nullable=True)
    decision_note = Column(Text, nullable=True)

    # Synthetic demo history (scripts/seed_demo_users.py only)
    is_seed = Column(Boolean, nullable=False, default=False, server_default=false())

    __table_args__ = (
        # At most one pending request per user, enforced by the database so
        # two simultaneous submissions can't both succeed (PostgreSQL).
        Index(
            "uq_access_requests_one_pending_per_user",
            "requester_id",
            unique=True,
            postgresql_where=text("status = 'pending'"),
        ),
    )
