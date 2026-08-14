from app.threat_intel.correlation import (
    correlate_indicators,
)
from app.threat_intel.schemas import ThreatIndicator


def make_indicator(
    *,
    indicator_type: str = "IP",
    severity: str = "HIGH",
    source: str = "pytest",
    reputation: int = 50,
    confidence: int = 70,
    tags: list[str] | None = None,
) -> ThreatIndicator:
    return ThreatIndicator(
        value="198.51.100.1",
        type=indicator_type,
        source=source,
        severity=severity,
        reputation=reputation,
        confidence=confidence,
        tags=tags or [],
    )


def test_correlation_identifies_strong_relationship():
    left = make_indicator(
        indicator_type="IP",
        severity="HIGH",
        source="pytest",
        reputation=50,
        confidence=70,
        tags=["ip", "high"],
    )

    right = make_indicator(
        indicator_type="IP",
        severity="HIGH",
        source="pytest",
        reputation=60,
        confidence=80,
        tags=["ip", "high"],
    )

    result = correlate_indicators(
        left,
        right,
    )

    assert result.score == 100
    assert result.related is True

    assert "Same indicator type" in result.reasons
    assert "Same severity" in result.reasons
    assert "Same intelligence source" in result.reasons
    assert "Similar reputation" in result.reasons
    assert "Similar confidence" in result.reasons
    assert "Shared tags: high, ip" in result.reasons


def test_correlation_identifies_unrelated_indicators():
    left = make_indicator(
        indicator_type="IP",
        severity="HIGH",
        source="source-a",
        reputation=10,
        confidence=10,
        tags=["ip"],
    )

    right = make_indicator(
        indicator_type="DOMAIN",
        severity="LOW",
        source="source-b",
        reputation=90,
        confidence=90,
        tags=["domain"],
    )

    result = correlate_indicators(
        left,
        right,
    )

    assert result.score == 0
    assert result.related is False
    assert result.reasons == []


def test_correlation_threshold_is_60():
    left = make_indicator(
        indicator_type="IP",
        severity="HIGH",
        source="source-a",
        reputation=50,
        confidence=10,
        tags=[],
    )

    right = make_indicator(
        indicator_type="IP",
        severity="LOW",
        source="source-a",
        reputation=90,
        confidence=90,
        tags=[],
    )

    result = correlate_indicators(
        left,
        right,
    )

    # Same type = 20
    # Same source = 15
    # Total = 35
    assert result.score == 35
    assert result.related is False


def test_correlation_includes_confidence():
    left = make_indicator(
        confidence=40,
    )

    right = make_indicator(
        confidence=50,
    )

    result = correlate_indicators(
        left,
        right,
    )

    assert "Similar confidence" in result.reasons


def test_correlation_rejects_dissimilar_confidence():
    left = make_indicator(
        confidence=10,
    )

    right = make_indicator(
        confidence=50,
    )

    result = correlate_indicators(
        left,
        right,
    )

    assert "Similar confidence" not in result.reasons


def test_correlation_shared_tags_are_deterministic():
    left = make_indicator(
        tags=[
            "malicious",
            "ip",
            "high-risk",
        ],
    )

    right = make_indicator(
        tags=[
            "high-risk",
            "ip",
            "external",
        ],
    )

    result = correlate_indicators(
        left,
        right,
    )

    assert (
        "Shared tags: high-risk, ip"
        in result.reasons
    )