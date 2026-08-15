import pytest

from app.core.database import SessionLocal
from app.threat_intel import service
from app.threat_intel.models import Indicator
from app.models.audit import AuditEvent
from app.threat_intel.providers.manager import ThreatProviderManager
from app.threat_intel.schemas import ThreatIndicator


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
            "Simulated provider failure"
        )


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
    assert indicators[0].source == "ValidProvider"


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
    assert indicators[0].source == "ValidProvider"


TEST_VALUE = "203.0.113.250"


def delete_test_indicator():
    db = SessionLocal()

    try:
        db.query(Indicator).filter(
            Indicator.value == TEST_VALUE
        ).delete(
            synchronize_session=False
        )

        db.commit()

    finally:
        db.close()


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


@pytest.mark.asyncio
async def test_ingestion_persists_enriched_indicator(monkeypatch):
    delete_test_indicator()

    original_manager = service.provider_manager

    service.provider_manager = type(
        "FakeManager",
        (),
        {
            "collect_all": (
                lambda self:
                FakeProvider().collect_indicators()
            )
        },
    )()

    db = SessionLocal()

    try:
        added = await service.ingest_threat_intelligence(
            db
        )

        assert added == 1

        indicator = (
            db.query(Indicator)
            .filter(
                Indicator.value == TEST_VALUE
            )
            .first()
        )

        assert indicator is not None
        assert indicator.source == "TestProvider"
        assert indicator.severity == "HIGH"

        assert indicator.threat_score == 85
        assert indicator.reputation_score == 40

        assert indicator.confidence_score >= 0
        assert indicator.confidence_score <= 100

        assert indicator.tags

    finally:
        db.close()
        service.provider_manager = original_manager
        delete_test_indicator()

@pytest.mark.asyncio
async def test_ingestion_records_audit_event(monkeypatch):
    """
    Successful threat-intelligence ingestion must persist an
    AUTO_INGEST_INDICATOR audit event together with the indicator.
    """

    audit_test_value = "203.0.113.248"

    db = SessionLocal()

    try:
        # Ensure the test starts clean.
        db.query(Indicator).filter(
            Indicator.value == audit_test_value
        ).delete(
            synchronize_session=False
        )

        db.query(AuditEvent).filter(
            AuditEvent.target == audit_test_value
        ).delete(
            synchronize_session=False
        )

        db.commit()

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
            return (
                await AuditProvider()
                .collect_indicators()
            )

        monkeypatch.setattr(
            service.provider_manager,
            "collect_all",
            mock_collect_all,
        )

        added = await service.ingest_threat_intelligence(
            db
        )

        assert added == 1

        indicator = (
            db.query(Indicator)
            .filter(
                Indicator.value == audit_test_value
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

        db.query(AuditEvent).filter(
            AuditEvent.target == audit_test_value
        ).delete(
            synchronize_session=False
        )

        db.query(Indicator).filter(
            Indicator.value == audit_test_value
        ).delete(
            synchronize_session=False
        )

        db.commit()
        db.close()


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

    from app.models.alert import Alert

    db = SessionLocal()

    try:
        # Ensure the test starts clean.
        db.query(Indicator).filter(
            Indicator.value == rollback_test_value
        ).delete(
            synchronize_session=False
        )

        db.query(Alert).filter(
            Alert.title
            == f"Threat Indicator: {rollback_test_value}"
        ).delete(
            synchronize_session=False
        )

        db.query(AuditEvent).filter(
            AuditEvent.target == rollback_test_value
        ).delete(
            synchronize_session=False
        )

        audit = (
            db.query(AuditEvent)
            .filter(
                AuditEvent.target == rollback_test_value
            )
            .first()
        )

        assert audit is None

        db.commit()

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
                "Simulated audit failure"
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
                db
            )

        # Indicator must not survive.
        assert (
            db.query(Indicator)
            .filter(
                Indicator.value
                == rollback_test_value
            )
            .first()
            is None
        )

        # Automatically generated alert must not survive.
        assert (
            db.query(Alert)
            .filter(
                Alert.title
                == (
                    "Threat Indicator: "
                    f"{rollback_test_value}"
                )
            )
            .first()
            is None
        )

        # Audit event must not survive.
        assert (
            db.query(AuditEvent)
            .filter(
                AuditEvent.target
                == rollback_test_value
            )
            .first()
            is None
        )

    finally:
        db.rollback()

        db.query(AuditEvent).filter(
            AuditEvent.target == rollback_test_value
        ).delete(
            synchronize_session=False
        )

        db.query(Indicator).filter(
            Indicator.value == rollback_test_value
        ).delete(
            synchronize_session=False
        )

        db.query(Alert).filter(
            Alert.title
            == f"Threat Indicator: {rollback_test_value}"
        ).delete(
            synchronize_session=False
        )

        db.commit()
        db.close()


@pytest.mark.asyncio
async def test_duplicate_indicator_is_skipped():
    delete_test_indicator()

    db = SessionLocal()

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

        original_manager = service.provider_manager

        service.provider_manager = type(
            "FakeManager",
            (),
            {
                "collect_all": (
                    lambda self:
                    FakeProvider().collect_indicators()
                )
            },
        )()

        try:
            added = (
                await service.ingest_threat_intelligence(
                    db
                )
            )

            assert added == 0

            count = (
                db.query(Indicator)
                .filter(
                    Indicator.value == TEST_VALUE
                )
                .count()
            )

            assert count == 1

        finally:
            service.provider_manager = original_manager

    finally:
        db.close()
        delete_test_indicator()


@pytest.mark.asyncio
async def test_low_indicator_does_not_create_alert():
    delete_test_indicator()

    db = SessionLocal()

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

        original_manager = service.provider_manager

        service.provider_manager = type(
            "FakeManager",
            (),
            {
                "collect_all": (
                    lambda self:
                    LowProvider().collect_indicators()
                )
            },
        )()

        try:
            added = (
                await service.ingest_threat_intelligence(
                    db
                )
            )

            assert added == 1

            indicator = (
                db.query(Indicator)
                .filter(
                    Indicator.value == TEST_VALUE
                )
                .first()
            )

            assert indicator is not None
            assert indicator.severity == "LOW"

        finally:
            service.provider_manager = original_manager

    finally:
        db.close()
        delete_test_indicator()

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
                "invalid": "response"
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


@pytest.mark.asyncio
async def test_ingestion_rolls_back_indicator_and_alert_on_failure(
    monkeypatch,
):
    """
    Threat-intelligence ingestion must be atomic.

    If an error occurs after an indicator and its alert have
    been created, both records must be rolled back together.
    """

    rollback_test_value = "203.0.113.249"

    db = SessionLocal()

    try:
        # Ensure the test starts clean.
        db.query(Indicator).filter(
            Indicator.value == rollback_test_value
        ).delete(
            synchronize_session=False
        )

        from app.models.alert import Alert

        db.query(Alert).filter(
            Alert.title
            == f"Threat Indicator: {rollback_test_value}"
        ).delete(
            synchronize_session=False
        )

        db.commit()

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
                "Simulated ingestion failure"
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
                db
            )

        # The indicator must not survive the rollback.
        indicator = (
            db.query(Indicator)
            .filter(
                Indicator.value
                == rollback_test_value
            )
            .first()
        )

        assert indicator is None

        # The automatically generated alert must
        # also be rolled back.
        alert = (
            db.query(Alert)
            .filter(
                Alert.title
                == (
                    "Threat Indicator: "
                    f"{rollback_test_value}"
                )
            )
            .first()
        )

        assert alert is None

    finally:
        # Cleanup in case the test itself fails before
        # the transaction rollback occurs.
        db.rollback()

        db.query(Indicator).filter(
            Indicator.value == rollback_test_value
        ).delete(
            synchronize_session=False
        )

        db.query(Alert).filter(
            Alert.title
            == f"Threat Indicator: {rollback_test_value}"
        ).delete(
            synchronize_session=False
        )

        db.commit()
        db.close()
