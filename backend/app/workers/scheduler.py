from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.schedulers.base import STATE_RUNNING

from app.workers.tasks import threat_intelligence_scan

scheduler = BackgroundScheduler()


def start_scheduler():
    if scheduler.state != STATE_RUNNING:
        scheduler.add_job(
            threat_intelligence_scan,
            trigger="interval",
            minutes=5,
            id="threat_intelligence_scan",
            replace_existing=True,
        )
        scheduler.start()
        print("✅ Background scheduler started")


def stop_scheduler():
    if scheduler.state == STATE_RUNNING:
        scheduler.shutdown()
        print("🛑 Background scheduler stopped")