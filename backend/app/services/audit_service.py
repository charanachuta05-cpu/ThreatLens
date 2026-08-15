from sqlalchemy.orm import Session

from app.models.audit import AuditEvent


def get_audit_events(
    db: Session,
    skip: int = 0,
    limit: int = 20,
    action: str | None = None,
    actor: str | None = None,
    target: str | None = None,
) -> list[AuditEvent]:
    """
    Retrieve persistent security audit events.

    Results are ordered newest first with ID as a
    deterministic tie-breaker.
    """

    query = db.query(AuditEvent)

    if action:
        query = query.filter(
            AuditEvent.action.ilike(f"%{action}%")
        )

    if actor:
        query = query.filter(
            AuditEvent.actor.ilike(f"%{actor}%")
        )

    if target:
        query = query.filter(
            AuditEvent.target.ilike(f"%{target}%")
        )

    query = query.order_by(
        AuditEvent.created_at.desc(),
        AuditEvent.id.desc(),
    )

    return (
        query
        .offset(skip)
        .limit(limit)
        .all()
    )
