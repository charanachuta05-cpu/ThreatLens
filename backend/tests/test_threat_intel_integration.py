import pytest

from app.core.database import SessionLocal
from app.models.alert import Alert
from app.threat_intel.models import Indicator
from app.threat_intel.schemas import ThreatIndicator
from app.threat_intel.service import ingest_threat_intelligence


TEST_VALUES = [
    "198.51.100.210",
    "198.51.100.211",
    "198.51.100.212",
]


@pytest.fixture(autouse=True)
def clean_integration_test_data():
    """
    Remove integration-test indicators and alerts
    before and after each test.
    """

    db = SessionLocal()

    try:
        db.query(Alert).filter(
            Alert.title.in_(
                [
                    f"Threat Indicator: {value}"
                    for value in TEST_VALUES
                ]
            )
        ).delete(
            synchronize_session=False
        )

        db.query(Indicator).filter(
            Indicator.value.in_(TEST_VALUES)
        ).delete(
            synchronize_session=False
        )

        db.commit()

        yield

    finally:
        db.query(Alert).filter(
            Alert.title.in_(
                [
                    f"Threat Indicator: {value}"
                    for value in TEST_VALUES
                ]
            )
        ).delete(
            synchronize_session=False
        )

        db.query(Indicator).filter(
            Indicator.value.in_(TEST_VALUES)
        ).delete(
            synchronize_session=False
        )

        db.commit()
        db.close()


@pytest.mark.asyncio
async def test_high_indicator_creates_alert(monkeypatch):
    """
    HIGH indicators should be enriched, persisted,
    and automatically generate an alert.
    """

    indicators = [
        ThreatIndicator(
            value="198.51.100.210",
            type="IP",
            source="pytest-integration",
            severity="HIGH",
        )
    ]

    async def mock_collect_all():
        return indicators

    monkeypatch.setattr(
        "app.threat_intel.service.provider_manager.collect_all",
        mock_collect_all,
    )

    db = SessionLocal()

    try:
        added = await ingest_threat_intelligence(db)

        assert added == 1

        indicator = (
            db.query(Indicator)
            .filter(
                Indicator.value == "198.51.100.210"
            )
            .first()
        )

        assert indicator is not None
        assert indicator.severity == "HIGH"

        assert indicator.threat_score > 0
        assert indicator.reputation_score >= 0
        assert indicator.confidence_score >= 0

        alert = (
            db.query(Alert)
            .filter(
                Alert.title
                == "Threat Indicator: 198.51.100.210"
            )
            .first()
        )

        assert alert is not None
        assert alert.severity.value == "HIGH"
        assert alert.source == "pytest-integration"
        assert alert.created_by == 1

    finally:
        db.close()


@pytest.mark.asyncio
async def test_medium_indicator_does_not_create_alert(
    monkeypatch,
):
    """
    MEDIUM indicators should be enriched and persisted
    but should not automatically generate an alert.
    """

    indicators = [
        ThreatIndicator(
            value="198.51.100.211",
            type="IP",
            source="pytest-integration",
            severity="MEDIUM",
        )
    ]

    async def mock_collect_all():
        return indicators

    monkeypatch.setattr(
        "app.threat_intel.service.provider_manager.collect_all",
        mock_collect_all,
    )

    db = SessionLocal()

    try:
        added = await ingest_threat_intelligence(db)

        assert added == 1

        indicator = (
            db.query(Indicator)
            .filter(
                Indicator.value == "198.51.100.211"
            )
            .first()
        )

        assert indicator is not None
        assert indicator.severity == "MEDIUM"

        assert indicator.threat_score > 0
        assert indicator.reputation_score >= 0
        assert indicator.confidence_score >= 0

        alert = (
            db.query(Alert)
            .filter(
                Alert.title
                == "Threat Indicator: 198.51.100.211"
            )
            .first()
        )

        assert alert is None

    finally:
        db.close()


@pytest.mark.asyncio
async def test_duplicate_indicator_is_not_inserted(
    monkeypatch,
):
    """
    Existing indicators should be skipped during ingestion.
    """

    indicators = [
        ThreatIndicator(
            value="198.51.100.210",
            type="IP",
            source="pytest-integration",
            severity="HIGH",
        )
    ]

    async def mock_collect_all():
        return indicators

    monkeypatch.setattr(
        "app.threat_intel.service.provider_manager.collect_all",
        mock_collect_all,
    )

    db = SessionLocal()

    try:
        first_added = await ingest_threat_intelligence(db)

        second_added = await ingest_threat_intelligence(db)

        assert first_added == 1
        assert second_added == 0

        count = (
            db.query(Indicator)
            .filter(
                Indicator.value
                == "198.51.100.210"
            )
            .count()
        )

        assert count == 1

    finally:
        db.close()

@pytest.mark.asyncio
async def test_provider_enrichment_flows_through_full_ingestion_pipeline(
    monkeypatch,
):
    """
    Provider enrichment must flow through the complete
    ingestion pipeline while preserving the original
    feed source.
    """

    value = "198.51.100.212"

    class EnrichmentProvider:
        provider_name = "ExternalIntelProvider"

        async def get_indicator_report(
            self,
            indicator_type: str,    
            value: str,
        ):
            return ThreatIndicator(
                value=value,
                type=indicator_type,
                source=self.provider_name,
                severity="CRITICAL",
                malicious=4,
                suspicious=2,
                harmless=10,
                tags=["provider-intel", "malware"],
            )

    indicator = ThreatIndicator(
        value=value,
        type="IP",
        source="pytest-feed",
        severity="MEDIUM",
        malicious=1,
        suspicious=1,
        harmless=5,
        tags=["feed"],
    )

    class IntegrationManager:
        providers = [EnrichmentProvider()]

        async def collect_all(self):
            return [indicator]

    monkeypatch.setattr(
        "app.threat_intel.service.provider_manager",
        IntegrationManager(),
    )

    db = SessionLocal()

    try:
        added = await ingest_threat_intelligence(db)

        assert added == 1

        stored = (
            db.query(Indicator)
            .filter(
                Indicator.value == value
            )
            .first()
        )

        assert stored is not None

        # Original feed identity must be preserved.
        assert stored.value == value
        assert stored.indicator_type == "IP"

        # Provider severity must enhance, not replace
        # the original source.
        assert stored.severity == "CRITICAL"
        assert stored.source == "pytest-feed"

        # Provider intelligence must contribute to
        # the locally calculated reputation score.
        assert stored.reputation_score > 0

        # Threat and confidence scores must be calculated.
        assert stored.threat_score == 100
        assert 0 <= stored.confidence_score <= 100

        # Original and provider tags must survive.
        assert "feed" in stored.tags
        assert "provider-intel" in stored.tags
        assert "malware" in stored.tags

        # CRITICAL enrichment must generate an alert.
        alert = (
            db.query(Alert)
            .filter(
                Alert.title
                == f"Threat Indicator: {value}"
            )
            .first()
        )

        assert alert is not None
        assert alert.severity.value == "CRITICAL"

        # Alert source must remain the original feed source.
        assert alert.source == "pytest-feed"

    finally:
        db.close()