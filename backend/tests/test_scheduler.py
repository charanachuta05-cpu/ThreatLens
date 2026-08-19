from unittest.mock import MagicMock

import app.workers.scheduler as scheduler_module


def test_start_scheduler_uses_configured_interval(monkeypatch):
    scheduler = MagicMock()
    scheduler.running = False

    monkeypatch.setattr(
        scheduler_module,
        "scheduler",
        scheduler,
    )

    monkeypatch.setattr(
        scheduler_module.settings,
        "THREAT_INTEL_INGEST_INTERVAL_MINUTES",
        10,
    )

    scheduler_module.start_scheduler()

    scheduler.add_job.assert_called_once_with(
        scheduler_module.threat_feed_job,
        "interval",
        minutes=10,
        id="threat_feed_worker",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
        misfire_grace_time=60,
    )

    scheduler.start.assert_called_once()


def test_start_scheduler_does_not_start_when_already_running(
    monkeypatch,
):
    scheduler = MagicMock()
    scheduler.running = True

    monkeypatch.setattr(
        scheduler_module,
        "scheduler",
        scheduler,
    )

    scheduler_module.start_scheduler()

    scheduler.add_job.assert_not_called()
    scheduler.start.assert_not_called()


def test_stop_scheduler_shuts_down_running_scheduler(
    monkeypatch,
):
    scheduler = MagicMock()
    scheduler.running = True

    monkeypatch.setattr(
        scheduler_module,
        "scheduler",
        scheduler,
    )

    scheduler_module.stop_scheduler()

    scheduler.shutdown.assert_called_once()


def test_stop_scheduler_does_nothing_when_not_running(
    monkeypatch,
):
    scheduler = MagicMock()
    scheduler.running = False

    monkeypatch.setattr(
        scheduler_module,
        "scheduler",
        scheduler,
    )

    scheduler_module.stop_scheduler()

    scheduler.shutdown.assert_not_called()
