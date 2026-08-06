import asyncio

from apscheduler.schedulers.background import BackgroundScheduler

from app.core.database import SessionLocal

from app.threat_intel.service import (
    ingest_threat_intelligence,
)


scheduler = BackgroundScheduler()


def threat_feed_job():

    db = SessionLocal()

    try:

        added = asyncio.run(
            ingest_threat_intelligence(db)
        )

        print(
            f"[Threat Worker] Added {added} new indicators"
        )

    except Exception as e:

        print(
            f"[Threat Worker] Error: {e}"
        )

    finally:
        db.close()



def start_scheduler():

    if not scheduler.running:

        scheduler.add_job(
            threat_feed_job,
            "interval",
            minutes=5,
            id="threat_feed_worker",
            replace_existing=True,
        )

        scheduler.start()



def stop_scheduler():

    if scheduler.running:
        scheduler.shutdown()