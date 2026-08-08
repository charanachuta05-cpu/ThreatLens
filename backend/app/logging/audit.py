from app.logging.logger import logger


def audit_event(
    action: str,
    actor: str,
    target: str,
):
    """
    Record an audit event.
    """

    logger.info(
        "[AUDIT] %s | Actor=%s | Target=%s",
        action,
        actor,
        target,
    )