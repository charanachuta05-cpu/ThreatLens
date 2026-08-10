from app.threat_intel.confidence import calculate_confidence
from app.threat_intel.reputation import calculate_reputation
from app.threat_intel.scoring import calculate_threat_score
from app.threat_intel.tags import generate_tags
from app.threat_intel.enrichment import enrich_indicator
from app.threat_intel.schemas import ThreatIndicator


def test_threat_score_by_severity():
    assert calculate_threat_score("LOW") == 30
    assert calculate_threat_score("MEDIUM") == 60
    assert calculate_threat_score("HIGH") == 85
    assert calculate_threat_score("CRITICAL") == 100


def test_threat_score_is_case_insensitive():
    assert calculate_threat_score("high") == 85
    assert calculate_threat_score(" Critical ") == 100


def test_reputation_score():
    indicator = ThreatIndicator(
        value="192.168.1.10",
        type="IP",
        source="test",
        severity="HIGH",
        malicious=3,
        suspicious=2,
        reputation=0,
        tags=[],
    )

    assert calculate_reputation(indicator) == 80


def test_reputation_score_is_capped():
    indicator = ThreatIndicator(
        value="192.168.1.10",
        type="IP",
        source="test",
        severity="CRITICAL",
        malicious=10,
        suspicious=10,
        reputation=0,
        tags=[],
    )

    assert calculate_reputation(indicator) == 100


def test_confidence_score():
    assert calculate_confidence(100, 100) == 100
    assert calculate_confidence(85, 80) == 83


def test_confidence_score_is_bounded():
    assert calculate_confidence(-50, 200) == 50
    assert calculate_confidence(1000, 1000) == 100


def test_tags_are_generated():
    indicator = ThreatIndicator(
        value="evil.example.com",
        type="DOMAIN",
        source="test",
        severity="CRITICAL",
        malicious=2,
        suspicious=1,
        reputation=10,
        tags=["APT", "Malware"],
    )

    tags = generate_tags(indicator)

    assert "domain" in tags
    assert "critical" in tags
    assert "high-risk" in tags
    assert "malicious" in tags
    assert "suspicious" in tags
    assert "poor-reputation" in tags
    assert "apt" in tags
    assert "malware" in tags


def test_full_enrichment_pipeline():
    indicator = ThreatIndicator(
        value="8.8.8.8",
        type="IP",
        source="test",
        severity="HIGH",
        malicious=3,
        suspicious=2,
        reputation=10,
        tags=["network"],
    )

    enriched = enrich_indicator(indicator)

    assert enriched.threat_score == 85
    assert enriched.reputation_score == 80
    assert enriched.confidence_score == 83

    assert "ip" in enriched.tags
    assert "high" in enriched.tags
    assert "high-risk" in enriched.tags
    assert "malicious" in enriched.tags
    assert "suspicious" in enriched.tags
    assert "poor-reputation" in enriched.tags
    assert "network" in enriched.tags