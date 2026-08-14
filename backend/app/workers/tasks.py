from datetime import datetime, timezone

from app.core.database import SessionLocal
from app.threat_intel.service import ingest_simulated_feed


def threat_intelligence_scan():
    db = SessionLocal()

    try:
        added = ingest_simulated_feed(db)

        print(
            f"[Threat Worker] {datetime.now(timezone.utc)} "
            f"Added {added} new indicators"
        )

    finally:
        db.close()