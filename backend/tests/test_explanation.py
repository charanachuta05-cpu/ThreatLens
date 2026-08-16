from app.threat_intel.explanation import (
    explain_confidence_score,
    explain_enrichment,
    explain_reputation_score,
    explain_tags,
    explain_threat_score,
)
from app.threat_intel.schemas import ThreatIndicator


def test_threat_score_explanation():
    indicator = ThreatIndicator(
        value="8.8.8.8",
        type="IP",
        source="test",
        severity="HIGH",
    )

    result = explain_threat_score(
        indicator,
    )

    assert result.value == 85

    assert result.reasons == [
        "HIGH severity contributes 85/100."
    ]


def test_reputation_explanation():
    indicator = ThreatIndicator(
        value="8.8.8.8",
        type="IP",
        source="test",
        severity="HIGH",
        malicious=3,
        suspicious=2,
    )

    result = explain_reputation_score(
        indicator,
    )

    assert result.value == 80

    assert (
        "3 malicious observations contribute 60 points."
        in result.reasons
    )

    assert (
        "2 suspicious observations contribute 20 points."
        in result.reasons
    )


def test_reputation_explanation_when_no_observations():
    indicator = ThreatIndicator(
        value="8.8.8.8",
        type="IP",
        source="test",
        severity="LOW",
    )

    result = explain_reputation_score(
        indicator,
    )

    assert result.value == 0

    assert result.reasons == [
        (
            "No malicious or suspicious observations "
            "contribute to the reputation evidence score."
        )
    ]


def test_reputation_explanation_mentions_cap():
    indicator = ThreatIndicator(
        value="8.8.8.8",
        type="IP",
        source="test",
        severity="CRITICAL",
        malicious=10,
        suspicious=10,
    )

    result = explain_reputation_score(
        indicator,
    )

    assert result.value == 100

    assert (
        "The reputation evidence score is capped at 100."
        in result.reasons
    )


def test_confidence_explanation():
    result = explain_confidence_score(
        threat_score=85,
        reputation_score=80,
    )

    assert result.value == 83

    assert (
        "60% threat score contribution: 51."
        in result.reasons
    )

    assert (
        "40% reputation evidence contribution: 32."
        in result.reasons
    )

    assert (
        "Weighted result rounds to 83/100."
        in result.reasons
    )


def test_tag_explanations():
    indicator = ThreatIndicator(
        value="evil.example.com",
        type="DOMAIN",
        source="test",
        severity="CRITICAL",
        reputation=10,
        malicious=2,
        suspicious=1,
        tags=["APT", "Malware"],
    )

    reasons = explain_tags(
        indicator,
    )

    assert reasons["domain"] == (
        "Indicator type is DOMAIN."
    )

    assert reasons["critical"] == (
        "Indicator severity is CRITICAL."
    )

    assert reasons["high-risk"] == (
        "Indicator severity is HIGH or CRITICAL."
    )

    assert reasons["malicious"] == (
        "Provider intelligence contains "
        "malicious observations."
    )

    assert reasons["suspicious"] == (
        "Provider intelligence contains "
        "suspicious observations."
    )

    assert reasons["poor-reputation"] == (
        "Provider-reported reputation is 20 or lower."
    )

    assert "apt" in reasons
    assert "malware" in reasons


def test_full_enrichment_explanation():
    indicator = ThreatIndicator(
        value="203.0.113.10",
        type="IP",
        source="test",
        severity="HIGH",
        reputation=10,
        malicious=3,
        suspicious=2,
        tags=["network"],
    )

    result = explain_enrichment(
        indicator,
    )

    assert result.threat_score.value == 85
    assert result.reputation_score.value == 80
    assert result.confidence_score.value == 83

    assert "high-risk" in result.tag_reasons
    assert "malicious" in result.tag_reasons
    assert "suspicious" in result.tag_reasons
    assert "poor-reputation" in result.tag_reasons
    assert "network" in result.tag_reasons
