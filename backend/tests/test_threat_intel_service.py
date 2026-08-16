import pytest

from app.core.database import SessionLocal
from app.models.alert import Alert
from app.models.audit import AuditEvent
from app.threat_intel import service
from app.threat_intel.models import Indicator
from app.threat_intel.providers.manager import ThreatProviderManager
from app.threat_intel.schemas import ThreatIndicator


# ============================================================
# TEST HELPERS
# ============================================================

TEST_VALUE = "203.0.113.250"


def delete_test_indicator(
    value: str = TEST_VALUE,
) -> None:
    """
    Remove all test data associated with an indicator.

    IMPORTANT:
    alerts must be deleted BEFORE indicators because alerts
    contain a foreign key to indicators.id.
    """

    db = SessionLocal()

    try:
        indicator = (
            db.query(Indicator)
            .filter(
                Indicator.value == value,
            )
            .first()
        )

        if indicator is not None:
            db.query(Alert).filter(
                Alert.indicator_id == indicator.id,
            ).delete(
                synchronize_session=False,
            )

        # Also remove historical/fallback alerts that may have
        # been created before indicator_id existed.
        db.query(Alert).filter(
            Alert.title == f"Threat Indicator: {value}",
        ).delete(
            synchronize_session=False,
        )

        db.query(AuditEvent).filter(
            AuditEvent.target == value,
        ).delete(
            synchronize_session=False,
        )

        # Indicator is deleted only AFTER dependent alerts.
        db.query(Indicator).filter(
            Indicator.value == value,
        ).delete(
            synchronize_session=False,
        )

        db.commit()

    finally:
        db.close()


def delete_alert_by_indicator_value(
    db,
    value: str,
) -> None:
    """
    Delete alerts associated with an indicator value.

    This helper is intentionally executed before indicator
    deletion to respect the FK relationship.
    """

    indicator = (
        db.query(Indicator)
        .filter(
            Indicator.value == value,
        )
        .first()
    )

    if indicator is not None:
        db.query(Alert).filter(
            Alert.indicator_id == indicator.id,
        ).delete(
            synchronize_session=False,
        )

    db.query(Alert).filter(
        Alert.title == f"Threat Indicator: {value}",
    ).delete(
        synchronize_session=False,
    )


# ============================================================
# GENERATED ALERT TESTS
# ============================================================


def test_generated_alert_is_linked_to_indicator():
    """
    HIGH indicators must generate an alert containing the
    direct indicator_id relationship.
    """

    delete_test_indicator()

    db = SessionLocal()

    try:
        indicator = Indicator(
            indicator_type="IP",
            value=TEST_VALUE,
            severity="HIGH",
            source="TestProvider",
            threat_score=90,
            reputation_score=80,
            confidence_score=85,
            tags="ip,high-risk",
        )

        db.add(indicator)
        db.commit()
        db.refresh(indicator)

        alert = service.generate_alert_for_indicator(
            db,
            indicator,
        )

        assert alert is not None
        assert alert.indicator_id == indicator.id

        db.commit()

        persisted_alert = (
            db.query(Alert)
            .filter(
                Alert.id == alert.id,
            )
            .first()
        )

        assert persisted_alert is not None
        assert persisted_alert.indicator_id == indicator.id

    finally:
        db.rollback()

        # Delete dependent alert first.
        delete_alert_by_indicator_value(
            db,
            TEST_VALUE,
        )

        db.query(AuditEvent).filter(
            AuditEvent.target == TEST_VALUE,
        ).delete(
            synchronize_session=False,
        )

        db.query(Indicator).filter(
            Indicator.value == TEST_VALUE,
        ).delete(
            synchronize_session=False,
        )

        db.commit()
        db.close()


def test_generated_alert_is_not_duplicated():
    """
    A single indicator must not generate multiple alerts.
    """

    delete_test_indicator()

    db = SessionLocal()

    try:
        indicator = Indicator(
            indicator_type="IP",
            value=TEST_VALUE,
            severity="CRITICAL",
            source="TestProvider",
            threat_score=100,
            reputation_score=95,
            confidence_score=95,
            tags="ip,critical",
        )

        db.add(indicator)
        db.commit()
        db.refresh(indicator)

        first_alert = (
            service.generate_alert_for_indicator(
                db,
                indicator,
            )
        )

        assert first_alert is not None
        assert first_alert.indicator_id == indicator.id

        db.commit()

        second_alert = (
            service.generate_alert_for_indicator(
                db,
                indicator,
            )
        )

        assert second_alert is None

        count = (
            db.query(Alert)
            .filter(
                Alert.indicator_id == indicator.id,
            )
            .count()
        )

        assert count == 1

    finally:
        db.rollback()

        delete_alert_by_indicator_value(
            db,
            TEST_VALUE,
        )

        db.query(AuditEvent).filter(
            AuditEvent.target == TEST_VALUE,
        ).delete(
            synchronize_session=False,
        )

        db.query(Indicator).filter(
            Indicator.value == TEST_VALUE,
        ).delete(
            synchronize_session=False,
        )

        db.commit()
        db.close()


# ============================================================
# PROVIDER TEST FIXTURES
# ============================================================


class SuccessfulProvider:
    @property
    def provider_name(self):
        return "SuccessfulProvider"

    async def collect_indicators(self):
        return [
            ThreatIndicator(
                value="203.0.113.10",
                type="IP",
                source="SuccessfulProvider",
                severity="HIGH",
            )
        ]


class FailingProvider:
    @property
    def provider_name(self):
        return "FailingProvider"

    async def collect_indicators(self):
        raise RuntimeError(
            "Simulated provider failure",
        )


class FakeProvider:
    provider_name = "TestProvider"

    async def collect_indicators(self):
        return [
            ThreatIndicator(
                value=TEST_VALUE,
                type="IP",
                source="TestProvider",
                severity="HIGH",
                malicious=2,
                suspicious=0,
                harmless=5,
                tags=["malware", "c2"],
            )
        ]


# ============================================================
# PROVIDER MANAGER TESTS
# ============================================================


@pytest.mark.asyncio
async def test_provider_failure_does_not_stop_other_providers():
    manager = ThreatProviderManager(
        providers=[
            FailingProvider(),
            SuccessfulProvider(),
        ]
    )

    indicators = await manager.collect_all()

    assert len(indicators) == 1
    assert indicators[0].value == "203.0.113.10"
    assert indicators[0].source == "SuccessfulProvider"


@pytest.mark.asyncio
async def test_provider_returning_none_is_skipped():
    class EmptyProvider:
        @property
        def provider_name(self):
            return "EmptyProvider"

        async def collect_indicators(self):
            return None

    class ValidProvider:
        @property
        def provider_name(self):
            return "ValidProvider"

        async def collect_indicators(self):
            return [
                ThreatIndicator(
                    value="203.0.113.252",
                    type="IP",
                    source="ValidProvider",
                    severity="MEDIUM",
                )
            ]

    manager = ThreatProviderManager(
        providers=[
            EmptyProvider(),
            ValidProvider(),
        ]
    )

    indicators = await manager.collect_all()

    assert len(indicators) == 1
    assert indicators[0].value == "203.0.113.252"


@pytest.mark.asyncio
async def test_invalid_provider_results_are_skipped():
    class InvalidProvider:
        @property
        def provider_name(self):
            return "InvalidProvider"

        async def collect_indicators(self):
            return [
                "not-a-threat-indicator",
                123,
                None,
            ]

    class ValidProvider:
        @property
        def provider_name(self):
            return "ValidProvider"

        async def collect_indicators(self):
            return [
                ThreatIndicator(
                    value="203.0.113.251",
                    type="IP",
                    source="ValidProvider",
                    severity="HIGH",
                )
            ]

    manager = ThreatProviderManager(
        providers=[
            InvalidProvider(),
            ValidProvider(),
        ]
    )

    indicators = await manager.collect_all()

    assert len(indicators) == 1
    assert indicators[0].value == "203.0.113.251"


@pytest.mark.asyncio
async def test_provider_returning_empty_list_is_skipped():
    class EmptyListProvider:
        @property
        def provider_name(self):
            return "EmptyListProvider"

        async def collect_indicators(self):
            return []

    class ValidProvider:
        @property
        def provider_name(self):
            return "ValidProvider"

        async def collect_indicators(self):
            return [
                ThreatIndicator(
                    value="203.0.113.251",
                    type="IP",
                    source="ValidProvider",
                    severity="MEDIUM",
                )
            ]

    manager = ThreatProviderManager(
        providers=[
            EmptyListProvider(),
            ValidProvider(),
        ]
    )

    indicators = await manager.collect_all()

    assert len(indicators) == 1
    assert indicators[0].value == "203.0.113.251"


@pytest.mark.asyncio
async def test_provider_returning_invalid_type_is_skipped():
    class InvalidTypeProvider:
        @property
        def provider_name(self):
            return "InvalidTypeProvider"

        async def collect_indicators(self):
            return {
                "invalid": "response",
            }

    class ValidProvider:
        @property
        def provider_name(self):
            return "ValidProvider"

        async def collect_indicators(self):
            return [
                ThreatIndicator(
                    value="203.0.113.253",
                    type="IP",
                    source="ValidProvider",
                    severity="LOW",
                )
            ]

    manager = ThreatProviderManager(
        providers=[
            InvalidTypeProvider(),
            ValidProvider(),
        ]
    )

    indicators = await manager.collect_all()

    assert len(indicators) == 1
    assert indicators[0].value == "203.0.113.253"


@pytest.mark.asyncio
async def test_provider_mixed_results_keep_only_valid_indicators():
    class MixedProvider:
        @property
        def provider_name(self):
            return "MixedProvider"

        async def collect_indicators(self):
            return [
                ThreatIndicator(
                    value="203.0.113.254",
                    type="IP",
                    source="MixedProvider",
                    severity="HIGH",
                ),
                "invalid",
                None,
            ]

    manager = ThreatProviderManager(
        providers=[
            MixedProvider(),
        ]
    )

    indicators = await manager.collect_all()

    assert len(indicators) == 1
    assert indicators[0].value == "203.0.113.254"


# ============================================================
# INGESTION TEST
# ============================================================


@pytest.mark.asyncio
async def test_ingestion_persists_enriched_indicator(
    monkeypatch,
):
    delete_test_indicator()

    original_manager = service.provider_manager

    service.provider_manager = type(
        "FakeManager",
        (),
        {
            "collect_all": (
                lambda self:
                FakeProvider().collect_indicators()
            ),
        },
    )()

    db = SessionLocal()

    try:
        added = (
            await service.ingest_threat_intelligence(
                db,
            )
        )

        assert added == 1

        indicator = (
            db.query(Indicator)
            .filter(
                Indicator.value == TEST_VALUE,
            )
            .first()
        )

        assert indicator is not None
        assert indicator.source == "TestProvider"
        assert indicator.severity == "HIGH"

        assert indicator.threat_score == 85
        assert indicator.reputation_score == 40

        assert 0 <= indicator.confidence_score <= 100
        assert indicator.tags

        # HIGH indicator must have a linked alert.
        alert = (
            db.query(Alert)
            .filter(
                Alert.indicator_id == indicator.id,
            )
            .first()
        )

        assert alert is not None
        assert alert.indicator_id == indicator.id

    finally:
        service.provider_manager = original_manager

        db.rollback()

        # Alert first, indicator second.
        delete_alert_by_indicator_value(
            db,
            TEST_VALUE,
        )

        db.query(AuditEvent).filter(
            AuditEvent.target == TEST_VALUE,
        ).delete(
            synchronize_session=False,
        )

        db.query(Indicator).filter(
            Indicator.value == TEST_VALUE,
        ).delete(
            synchronize_session=False,
        )

        db.commit()
        db.close()


# ============================================================
# AUDIT TEST
# ============================================================


@pytest.mark.asyncio
async def test_ingestion_records_audit_event(
    monkeypatch,
):
    """
    Successful threat-intelligence ingestion must persist
    an AUTO_INGEST_INDICATOR audit event together with
    the indicator.
    """

    audit_test_value = "203.0.113.248"

    delete_test_indicator(
        audit_test_value,
    )

    db = SessionLocal()

    try:
        class AuditProvider:
            provider_name = "AuditTestProvider"

            async def collect_indicators(self):
                return [
                    ThreatIndicator(
                        value=audit_test_value,
                        type="IP",
                        source="AuditTestProvider",
                        severity="HIGH",
                    )
                ]

        async def mock_collect_all():
            return await AuditProvider().collect_indicators()

        monkeypatch.setattr(
            service.provider_manager,
            "collect_all",
            mock_collect_all,
        )

        added = (
            await service.ingest_threat_intelligence(
                db,
            )
        )

        assert added == 1

        indicator = (
            db.query(Indicator)
            .filter(
                Indicator.value == audit_test_value,
            )
            .first()
        )

        assert indicator is not None

        event = (
            db.query(AuditEvent)
            .filter(
                AuditEvent.target == audit_test_value,
                AuditEvent.action
                == "AUTO_INGEST_INDICATOR",
            )
            .first()
        )

        assert event is not None
        assert event.actor == "system"
        assert event.target == audit_test_value

    finally:
        db.rollback()

        delete_alert_by_indicator_value(
            db,
            audit_test_value,
        )

        db.query(AuditEvent).filter(
            AuditEvent.target == audit_test_value,
        ).delete(
            synchronize_session=False,
        )

        db.query(Indicator).filter(
            Indicator.value == audit_test_value,
        ).delete(
            synchronize_session=False,
        )

        db.commit()
        db.close()


# ============================================================
# DUPLICATE INDICATOR TEST
# ============================================================


@pytest.mark.asyncio
async def test_duplicate_indicator_is_skipped():
    delete_test_indicator()

    db = SessionLocal()

    original_manager = service.provider_manager

    try:
        existing = Indicator(
            indicator_type="IP",
            value=TEST_VALUE,
            severity="HIGH",
            source="ExistingProvider",
            threat_score=85,
            reputation_score=40,
            confidence_score=67,
            tags="ip,high-risk",
        )

        db.add(existing)
        db.commit()

        service.provider_manager = type(
            "FakeManager",
            (),
            {
                "collect_all": (
                    lambda self:
                    FakeProvider().collect_indicators()
                ),
            },
        )()

        added = (
            await service.ingest_threat_intelligence(
                db,
            )
        )

        assert added == 0

        count = (
            db.query(Indicator)
            .filter(
                Indicator.value == TEST_VALUE,
            )
            .count()
        )

        assert count == 1

    finally:
        service.provider_manager = original_manager

        db.rollback()

        delete_alert_by_indicator_value(
            db,
            TEST_VALUE,
        )

        db.query(AuditEvent).filter(
            AuditEvent.target == TEST_VALUE,
        ).delete(
            synchronize_session=False,
        )

        db.query(Indicator).filter(
            Indicator.value == TEST_VALUE,
        ).delete(
            synchronize_session=False,
        )

        db.commit()
        db.close()


# ============================================================
# LOW SEVERITY TEST
# ============================================================


@pytest.mark.asyncio
async def test_low_indicator_does_not_create_alert():
    delete_test_indicator()

    db = SessionLocal()

    original_manager = service.provider_manager

    try:
        class LowProvider:
            provider_name = "TestProvider"

            async def collect_indicators(self):
                return [
                    ThreatIndicator(
                        value=TEST_VALUE,
                        type="IP",
                        source="TestProvider",
                        severity="LOW",
                    )
                ]

        service.provider_manager = type(
            "FakeManager",
            (),
            {
                "collect_all": (
                    lambda self:
                    LowProvider().collect_indicators()
                ),
            },
        )()

        added = (
            await service.ingest_threat_intelligence(
                db,
            )
        )

        assert added == 1

        indicator = (
            db.query(Indicator)
            .filter(
                Indicator.value == TEST_VALUE,
            )
            .first()
        )

        assert indicator is not None
        assert indicator.severity == "LOW"

        alert = (
            db.query(Alert)
            .filter(
                Alert.indicator_id == indicator.id,
            )
            .first()
        )

        assert alert is None

    finally:
        service.provider_manager = original_manager

        db.rollback()

        delete_alert_by_indicator_value(
            db,
            TEST_VALUE,
        )

        db.query(AuditEvent).filter(
            AuditEvent.target == TEST_VALUE,
        ).delete(
            synchronize_session=False,
        )

        db.query(Indicator).filter(
            Indicator.value == TEST_VALUE,
        ).delete(
            synchronize_session=False,
        )

        db.commit()
        db.close()


# ============================================================
# TRANSACTION ROLLBACK TEST
# ============================================================


@pytest.mark.asyncio
async def test_ingestion_rolls_back_indicator_alert_on_failure(
    monkeypatch,
):
    """
    Threat-intelligence ingestion must be atomic.

    If an error occurs after an indicator and its alert have
    been created, both records must be rolled back together.
    """

    rollback_test_value = "203.0.113.249"

    delete_test_indicator(
        rollback_test_value,
    )

    db = SessionLocal()

    try:
        class RollbackProvider:
            provider_name = "RollbackProvider"

            async def collect_indicators(self):
                return [
                    ThreatIndicator(
                        value=rollback_test_value,
                        type="IP",
                        source="RollbackProvider",
                        severity="HIGH",
                    )
                ]

        async def mock_collect_all():
            return (
                await RollbackProvider()
                .collect_indicators()
            )

        monkeypatch.setattr(
            service.provider_manager,
            "collect_all",
            mock_collect_all,
        )

        def fail_audit_event(
            db,
            action,
            actor,
            target,
        ):
            raise RuntimeError(
                "Simulated ingestion failure",
            )

        monkeypatch.setattr(
            service,
            "audit_event",
            fail_audit_event,
        )

        with pytest.raises(
            RuntimeError,
            match="Simulated ingestion failure",
        ):
            await service.ingest_threat_intelligence(
                db,
            )

        # Indicator must not survive rollback.
        indicator = (
            db.query(Indicator)
            .filter(
                Indicator.value == rollback_test_value,
            )
            .first()
        )

        assert indicator is None

        # Alert must not survive rollback.
        alert = (
            db.query(Alert)
            .filter(
                Alert.title
                == (
                    "Threat Indicator: "
                    f"{rollback_test_value}"
                ),
            )
            .first()
        )

        assert alert is None

        # Audit event must not survive rollback.
        event = (
            db.query(AuditEvent)
            .filter(
                AuditEvent.target
                == rollback_test_value,
            )
            .first()
        )

        assert event is None

    finally:
        db.rollback()

        delete_alert_by_indicator_value(
            db,
            rollback_test_value,
        )

        db.query(AuditEvent).filter(
            AuditEvent.target == rollback_test_value,
        ).delete(
            synchronize_session=False,
        )

        db.query(Indicator).filter(
            Indicator.value == rollback_test_value,
        ).delete(
            synchronize_session=False,
        )

        db.commit()
        db.close()


# ============================================================
# AUDIT FAILURE ATOMICITY TEST
# ============================================================


@pytest.mark.asyncio
async def test_ingestion_rolls_back_indicator_alert_and_audit_event(
    monkeypatch,
):
    """
    Indicator, generated alert, and audit event must all
    participate in the same transaction.

    If audit logging fails, none of the records may survive.
    """

    rollback_test_value = "203.0.113.247"

    delete_test_indicator(
        rollback_test_value,
    )

    db = SessionLocal()

    try:
        class RollbackProvider:
            provider_name = "RollbackAuditProvider"

            async def collect_indicators(self):
                return [
                    ThreatIndicator(
                        value=rollback_test_value,
                        type="IP",
                        source="RollbackAuditProvider",
                        severity="HIGH",
                    )
                ]

        async def mock_collect_all():
            return (
                await RollbackProvider()
                .collect_indicators()
            )

        monkeypatch.setattr(
            service.provider_manager,
            "collect_all",
            mock_collect_all,
        )

        def fail_audit_event(
            db,
            action,
            actor,
            target,
        ):
            raise RuntimeError(
                "Simulated audit failure",
            )

        monkeypatch.setattr(
            service,
            "audit_event",
            fail_audit_event,
        )

        with pytest.raises(
            RuntimeError,
            match="Simulated audit failure",
        ):
            await service.ingest_threat_intelligence(
                db,
            )

        assert (
            db.query(Indicator)
            .filter(
                Indicator.value
                == rollback_test_value,
            )
            .first()
            is None
        )

        assert (
            db.query(Alert)
            .filter(
                Alert.title
                == (
                    "Threat Indicator: "
                    f"{rollback_test_value}"
                ),
            )
            .first()
            is None
        )

        assert (
            db.query(AuditEvent)
            .filter(
                AuditEvent.target
                == rollback_test_value,
            )
            .first()
            is None
        )

    finally:
        db.rollback()

        delete_alert_by_indicator_value(
            db,
            rollback_test_value,
        )

        db.query(AuditEvent).filter(
            AuditEvent.target == rollback_test_value,
        ).delete(
            synchronize_session=False,
        )

        db.query(Indicator).filter(
            Indicator.value == rollback_test_value,
        ).delete(
            synchronize_session=False,
        )

        db.commit()
        db.close()