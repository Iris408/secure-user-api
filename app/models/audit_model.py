from sqlalchemy import JSON, Column, DateTime, Integer, String, func

from app.database import Base


# =========================================
# EN: Audit events (append-only)
# JP: 監査イベント（追記のみ）
# KR: 감사 이벤트 (추가 전용)
# =========================================
#
# Actor and target are stored as snapshots (id, username, role) rather than
# foreign keys, so the history stays intact when a user is renamed or deleted.
# The application never updates or deletes rows, and on PostgreSQL a trigger
# (app/migrations.py) rejects UPDATE, DELETE and TRUNCATE on this table.

class AuditEvent(Base):

    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True)

    occurred_at = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )

    # One of app.audit.AuditEventType, e.g. "auth.sign_in"
    event_type = Column(String(64), nullable=False, index=True)

    # "success", "failure" or "denied"
    outcome = Column(String(16), nullable=False, index=True)

    # Who did it (null when unauthenticated, e.g. a failed sign-in)
    actor_id = Column(Integer, nullable=True, index=True)
    actor_username = Column(String, nullable=True)
    actor_role = Column(String, nullable=True)

    # What it was done to, where relevant
    target_type = Column(String(32), nullable=True)
    target_id = Column(Integer, nullable=True, index=True)
    target_username = Column(String, nullable=True)

    # Allow-listed, display-safe details only (see app.audit.safe_details)
    details = Column(JSON, nullable=False, default=dict)
