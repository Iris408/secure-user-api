from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.audit import AuditEventType, AuditOutcome, event_to_dict
from app.auth import CurrentUser, deny_access, require_permission
from app.database import get_db
from app.models.audit_model import AuditEvent
from app.permissions import Permission, Role, normalize_role


# =========================================
# EN: Audit log (read-only, admin only)
# JP: 監査ログ（読み取り専用・管理者のみ）
# KR: 감사 로그 (읽기 전용, 관리자 전용)
# =========================================
#
# There are deliberately no create, update or delete routes: events are only
# written by the application itself (app.audit.record_event).

router = APIRouter()

MAX_PAGE_SIZE = 100


def require_audit_admin(
    request: Request,
    current_user: CurrentUser = Depends(require_permission(Permission.AUDIT_READ)),
    db: Session = Depends(get_db),
) -> CurrentUser:
    # The role comes from the database (get_current_user), never the token.
    # audit:read is fixed to Admin in the policy; this role check is a second,
    # independent safeguard.
    if normalize_role(current_user.role) != Role.ADMIN:
        deny_access(db, request, current_user, Permission.AUDIT_READ, reason="admin_only")

    return current_user


def escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@router.get("/audit-events")
def list_audit_events(
    event_type: Optional[AuditEventType] = None,
    outcome: Optional[AuditOutcome] = None,
    q: Optional[str] = Query(None, max_length=100, description="Actor or target username contains"),
    since: Optional[datetime] = Query(None, description="ISO 8601, inclusive"),
    until: Optional[datetime] = Query(None, description="ISO 8601, exclusive"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=MAX_PAGE_SIZE),
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(require_audit_admin),
):
    if since and until and since >= until:
        raise HTTPException(status_code=400, detail="'since' must be earlier than 'until'")

    query = db.query(AuditEvent)

    if event_type:
        query = query.filter(AuditEvent.event_type == event_type.value)

    if outcome:
        query = query.filter(AuditEvent.outcome == outcome.value)

    if q and q.strip():
        pattern = f"%{escape_like(q.strip())}%"
        query = query.filter(or_(
            AuditEvent.actor_username.ilike(pattern, escape="\\"),
            AuditEvent.target_username.ilike(pattern, escape="\\"),
        ))

    if since:
        query = query.filter(AuditEvent.occurred_at >= since)

    if until:
        query = query.filter(AuditEvent.occurred_at < until)

    total = query.count()
    events = (
        query.order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return {
        "events": [event_to_dict(event) for event in events],
        "total": total,
        "page": page,
        "page_size": page_size,
    }
