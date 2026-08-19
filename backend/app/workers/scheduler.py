import asyncio
import logging

from apscheduler.schedulers.background import BackgroundScheduler

from app.core.config import settings
from app.core.database import SessionLocal
from app.threat_intel.service import (
    ingest_threat_intelligence,
)


logger = logging.getLogger(__name__)


scheduler = BackgroundScheduler()


def threat_feed_job():
    """
    Execute the scheduled threat-intelligence ingestion job.

    Only one ingestion execution is allowed at a time by the
    scheduler configuration.
    """

    db = SessionLocal()

    try:
        added = asyncio.run(
            ingest_threat_intelligence(db)
        )

        logger.info(
            "Threat intelligence job completed. "
            "Added %s new indicators.",
            added,
        )

    except Exception:
        logger.exception(
            "Threat intelligence scheduled job failed."
        )

    finally:
        db.close()


def start_scheduler():
    """
    Start the background threat-intelligence scheduler.

    The job interval is controlled by application configuration.
    """

    if scheduler.running:
        return

    scheduler.add_job(
        threat_feed_job,
        "interval",
        minutes=settings.THREAT_INTEL_INGEST_INTERVAL_MINUTES,
        id="threat_feed_worker",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
        misfire_grace_time=60,
    )

    scheduler.start()

    logger.info(
        "Threat intelligence scheduler started. "
        "Interval: %s minutes.",
        settings.THREAT_INTEL_INGEST_INTERVAL_MINUTES,
    )


def stop_scheduler():
    """
    Stop the background scheduler if it is running.
    """

    if scheduler.running:
        scheduler.shutdown()

        logger.info(
            "Threat intelligence scheduler stopped."
        )
