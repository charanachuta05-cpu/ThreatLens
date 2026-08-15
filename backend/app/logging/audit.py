from sqlalchemy.orm import Session

from app.logging.logger import logger
from app.models.audit import AuditEvent


def audit_event(
    db: Session,
    action: str,
    actor: str,
    target: str,
) -> AuditEvent:
    """
    Record a persistent security audit event.

    The event is added to the caller's SQLAlchemy session and
    flushed, but deliberately not committed. The caller owns
    the transaction, allowing the audit record to succeed or
    roll back atomically with the operation being audited.
    """

    event = AuditEvent(
        action=action,
        actor=actor,
        target=target,
    )

    db.add(event)
    db.flush()

    logger.info(
        "[AUDIT] %s | Actor=%s | Target=%s",
        action,
        actor,
        target,
    )

    return event
