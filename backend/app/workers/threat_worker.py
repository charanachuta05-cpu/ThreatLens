import logging

from app.core.database import SessionLocal
from app.threat_intel.service import (
    ingest_threat_intelligence,
)

logger = logging.getLogger(__name__)


async def run_threat_intelligence_job():
    """
    Background job for automatic threat feed ingestion.
    """

    db = SessionLocal()

    try:
        count = await ingest_threat_intelligence(db)

        logger.info(
            "Threat intelligence job completed. Added %s indicators",
            count,
        )

    except Exception as exc:
        logger.exception(
            "Threat intelligence job failed: %s",
            exc,
        )

    finally:
        db.close()