from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, field_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.audit import AuditEventType, AuditOutcome, record_event
from app.auth import CurrentUser, get_active_user, require_permission
from app.database import get_db
from app.demo_seed import demo_mode
from app.models.access_request_model import AccessRequest, AccessRequestStatus
from app.models.user_model import User
from app.permissions import Permission, Role, normalize_role, parse_role
from app.settings import load_settings


# =========================================
# EN: Access requests
# JP: アクセス申請
# KR: 접근 요청
# =========================================
#
# Rules (all enforced here, never only in the UI):
# - Requests ask for Manager, Member or Viewer/Auditor; never Admin.
# - Anyone with access_requests:submit (Member, Manager) may submit; admins
#   already have full access. One pending request per user.
# - access_requests:review (Manager, Admin) sees the queue and history.
# - Only admins decide requests for Manager access; nobody decides their own.
# - A request is decided once. Approval changes the role, the request and the
#   audit log in one transaction.

router = APIRouter()

MAX_PAGE_SIZE = 100
REASON_MAX_LENGTH = 500
NOTE_MAX_LENGTH = 500
REQUESTABLE_ROLES = (Role.MANAGER, Role.MEMBER, Role.VIEWER)


class AccessRequestCreate(BaseModel):
    requested_role: str
    reason: str

    @field_validator("requested_role")
    @classmethod
    def _check_role(cls, value):
        role = parse_role(value)
        if role not in REQUESTABLE_ROLES:
            raise ValueError("Admin access can't be requested")
        return role.value

    @field_validator("reason")
    @classmethod
    def _check_reason(cls, value):
        value = value.strip()
        if len(value) < 3:
            raise ValueError("Reason must be at least 3 characters")
        if len(value) > REASON_MAX_LENGTH:
            raise ValueError(f"Reason must be at most {REASON_MAX_LENGTH} characters")
        return value


class DecisionRequest(BaseModel):
    note: Optional[str] = None

    @field_validator("note")
    @classmethod
    def _check_note(cls, value):
        if value is None:
            return None
        value = value.strip()
        if len(value) > NOTE_MAX_LENGTH:
            raise ValueError(f"Note must be at most {NOTE_MAX_LENGTH} characters")
        return value or None


def iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def decision_block_reason(request: AccessRequest, current_user: CurrentUser) -> Optional[str]:
    """Why `current_user` may not decide `request`, or None if they may."""

    if not current_user.can(Permission.ACCESS_REQUESTS_REVIEW):
        return "missing_permission"
    if request.requester_id == current_user.id:
        return "own_request"
    if (
        request.requested_role == Role.MANAGER.value
        and normalize_role(current_user.role) != Role.ADMIN
    ):
        return "manager_requires_admin"
    if request.status != AccessRequestStatus.PENDING:
        return "not_pending"
    return None


def request_to_dict(request: AccessRequest, live_users: dict, current_user: CurrentUser) -> dict:
    live = live_users.get(request.requester_id)
    block = decision_block_reason(request, current_user)

    return {
        "id": request.id,
        "status": request.status,
        "requested_role": request.requested_role,
        "reason": request.reason,
        "submitted_at": iso(request.submitted_at),
        "is_seed": bool(request.is_seed),
        "requester": {
            "id": request.requester_id,
            "username": request.requester_username,
            "role_at_submission": request.requester_role,
            # Live values; null when the account has since been deleted.
            "current_username": live.username if live else None,
            "current_role": normalize_role(live.role).value if live else None,
        },
        "decision": (
            {
                "decided_at": iso(request.decided_at),
                "note": request.decision_note,
                "reviewer": {
                    "id": request.reviewer_id,
                    "username": request.reviewer_username,
                    "role": request.reviewer_role,
                },
            }
            if request.status != AccessRequestStatus.PENDING
            else None
        ),
        "can_decide": block is None,
        "decision_block_reason": block,
    }


def serialize(db: Session, requests: list, current_user: CurrentUser) -> list:
    ids = {request.requester_id for request in requests}
    live_users = (
        {user.id: user for user in db.query(User).filter(User.id.in_(ids)).all()}
        if ids
        else {}
    )
    return [request_to_dict(request, live_users, current_user) for request in requests]


def requester_snapshot(request: AccessRequest):
    """Audit target for a request whose requester may no longer exist."""
    return SimpleNamespace(
        id=request.requester_id,
        username=request.requester_username,
        role=request.requester_role,
    )


def escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def paged(query, page: int, page_size: int):
    total = query.count()
    items = (
        query.order_by(AccessRequest.submitted_at.desc(), AccessRequest.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return items, total


# =========================================
# EN: Submit and view your own requests
# JP: 申請の送信と自分の申請の確認
# KR: 요청 제출 및 내 요청 보기
# =========================================

@router.post("/access-requests", status_code=201)
def submit_access_request(
    body: AccessRequestCreate,
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(require_permission(Permission.ACCESS_REQUESTS_SUBMIT)),
):
    user = db.get(User, current_user.id)
    current_role = normalize_role(user.role)

    if current_role == Role.ADMIN:
        raise HTTPException(status_code=400, detail="Administrators already have full access")

    # The organisation's request policy (Settings). It only narrows what may
    # be requested: Admin is never requestable, and approval rules still apply.
    policy = load_settings(db)
    if not policy.access_requests_enabled:
        raise HTTPException(status_code=403, detail="Access requests are turned off")
    if body.requested_role not in policy.requestable_roles:
        raise HTTPException(status_code=400, detail="This role can't be requested")

    if body.requested_role == current_role.value:
        raise HTTPException(status_code=400, detail="You already have this role")

    pending = db.query(AccessRequest.id).filter(
        AccessRequest.requester_id == user.id,
        AccessRequest.status == AccessRequestStatus.PENDING,
    ).first()

    if pending:
        raise HTTPException(status_code=409, detail="You already have a pending access request")

    request = AccessRequest(
        submitted_at=datetime.now(timezone.utc),
        requester_id=user.id,
        requester_username=user.username,
        requester_role=current_role.value,
        requested_role=body.requested_role,
        reason=body.reason,
        status=AccessRequestStatus.PENDING,
        # In a public demo every record is demo data.
        is_seed=demo_mode(),
    )
    db.add(request)

    try:
        db.flush()
    except IntegrityError:
        # A simultaneous submission won the one-pending-per-user index.
        db.rollback()
        raise HTTPException(status_code=409, detail="You already have a pending access request")

    record_event(
        db, AuditEventType.ACCESS_REQUEST_SUBMITTED, AuditOutcome.SUCCESS,
        actor=current_user, target=user,
        details={
            "request_id": request.id,
            "requested_role": request.requested_role,
            "role": current_role.value,
        },
    )
    db.commit()
    db.refresh(request)

    return {"request": serialize(db, [request], current_user)[0]}


@router.get("/access-requests/mine")
def my_access_requests(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=MAX_PAGE_SIZE),
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(get_active_user),
):
    query = db.query(AccessRequest).filter(AccessRequest.requester_id == current_user.id)
    requests, total = paged(query, page, page_size)

    return {
        "requests": serialize(db, requests, current_user),
        "total": total,
        "page": page,
        "page_size": page_size,
    }


# =========================================
# EN: Reviewer queue and history
# JP: レビュー担当者のキューと履歴
# KR: 검토자 대기열 및 기록
# =========================================

@router.get("/access-requests/summary")
def access_request_summary(
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(require_permission(Permission.ACCESS_REQUESTS_REVIEW)),
):
    query = db.query(AccessRequest).filter(AccessRequest.status == AccessRequestStatus.PENDING)
    recent, total = paged(query, 1, 5)

    return {
        "pending_total": total,
        "recent": serialize(db, recent, current_user),
    }


@router.get("/access-requests")
def list_access_requests(
    status: Optional[str] = Query(None, pattern="^(pending|approved|declined)$"),
    requested_role: Optional[str] = Query(None, pattern="^(manager|member|viewer)$"),
    q: Optional[str] = Query(None, max_length=100, description="Requester username contains"),
    since: Optional[datetime] = Query(None, description="Submitted at or after (ISO 8601)"),
    until: Optional[datetime] = Query(None, description="Submitted before (ISO 8601)"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=MAX_PAGE_SIZE),
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(require_permission(Permission.ACCESS_REQUESTS_REVIEW)),
):
    if since and until and since >= until:
        raise HTTPException(status_code=400, detail="'since' must be earlier than 'until'")

    query = db.query(AccessRequest)

    if status:
        query = query.filter(AccessRequest.status == status)
    if requested_role:
        query = query.filter(AccessRequest.requested_role == requested_role)
    if q and q.strip():
        query = query.filter(
            AccessRequest.requester_username.ilike(f"%{escape_like(q.strip())}%", escape="\\")
        )
    if since:
        query = query.filter(AccessRequest.submitted_at >= since)
    if until:
        query = query.filter(AccessRequest.submitted_at < until)

    requests, total = paged(query, page, page_size)

    return {
        "requests": serialize(db, requests, current_user),
        "total": total,
        "page": page,
        "page_size": page_size,
    }


# =========================================
# EN: Approve / decline
# JP: 承認 / 却下
# KR: 승인 / 거절
# =========================================

DENIAL_MESSAGES = {
    "own_request": "You can't review your own access request",
    "manager_requires_admin": "Only administrators can decide requests for Manager access",
}


def decide(
    db: Session,
    request_id: int,
    current_user: CurrentUser,
    approve: bool,
    note: Optional[str],
) -> dict:
    event_type = (
        AuditEventType.ACCESS_REQUEST_APPROVED if approve else AuditEventType.ACCESS_REQUEST_DECLINED
    )

    # Lock the request so two reviewers can't decide it at the same time.
    request = db.query(AccessRequest).filter(
        AccessRequest.id == request_id
    ).with_for_update().first()

    if request is None:
        raise HTTPException(status_code=404, detail="Access request not found")

    block = decision_block_reason(request, current_user)

    if block in DENIAL_MESSAGES:
        record_event(
            db, event_type, AuditOutcome.DENIED,
            actor=current_user, target=requester_snapshot(request),
            details={
                "request_id": request.id,
                "requested_role": request.requested_role,
                "reason": block,
            },
        )
        db.commit()
        raise HTTPException(status_code=403, detail=DENIAL_MESSAGES[block])

    if block == "not_pending":
        raise HTTPException(
            status_code=409, detail=f"This access request has already been {request.status}"
        )

    requester = db.query(User).filter(
        User.id == request.requester_id
    ).with_for_update().first()

    if approve:
        if requester is None:
            raise HTTPException(status_code=409, detail="The requester's account no longer exists")
        if not requester.is_active:
            raise HTTPException(status_code=409, detail="The requester's account is deactivated")
        if normalize_role(requester.role) == Role.ADMIN:
            raise HTTPException(status_code=409, detail="The requester is now an administrator")

        from_role = normalize_role(requester.role).value

        if from_role != request.requested_role:
            requester.role = request.requested_role
            record_event(
                db, AuditEventType.ROLE_CHANGED, AuditOutcome.SUCCESS,
                actor=current_user, target=requester,
                details={
                    "from_role": from_role,
                    "to_role": request.requested_role,
                    "reason": "access_request",
                    "request_id": request.id,
                },
            )

    request.status = AccessRequestStatus.APPROVED if approve else AccessRequestStatus.DECLINED
    request.reviewer_id = current_user.id
    request.reviewer_username = current_user.username
    request.reviewer_role = normalize_role(current_user.role).value
    request.decided_at = datetime.now(timezone.utc)
    request.decision_note = note

    record_event(
        db, event_type, AuditOutcome.SUCCESS,
        actor=current_user, target=requester or requester_snapshot(request),
        details={"request_id": request.id, "requested_role": request.requested_role},
    )

    # Role change, decision and audit events are committed together.
    db.commit()
    db.refresh(request)

    return {"request": serialize(db, [request], current_user)[0]}


@router.post("/access-requests/{request_id}/approve")
def approve_access_request(
    request_id: int,
    body: DecisionRequest = DecisionRequest(),
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(require_permission(Permission.ACCESS_REQUESTS_REVIEW)),
):
    return decide(db, request_id, current_user, approve=True, note=body.note)


@router.post("/access-requests/{request_id}/decline")
def decline_access_request(
    request_id: int,
    body: DecisionRequest = DecisionRequest(),
    db: Session = Depends(get_db),
    current_user: CurrentUser = Depends(require_permission(Permission.ACCESS_REQUESTS_REVIEW)),
):
    return decide(db, request_id, current_user, approve=False, note=body.note)
