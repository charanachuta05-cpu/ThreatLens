from dataclasses import dataclass

from app.threat_intel.confidence import calculate_confidence
from app.threat_intel.reputation import calculate_reputation
from app.threat_intel.scoring import calculate_threat_score
from app.threat_intel.schemas import ThreatIndicator


@dataclass(slots=True)
class ScoreExplanation:
    """
    Explain a calculated intelligence score.
    """

    value: int
    reasons: list[str]


@dataclass(slots=True)
class EnrichmentExplanation:
    """
    Deterministic explanation of the enrichment pipeline.
    """

    threat_score: ScoreExplanation
    reputation_score: ScoreExplanation
    confidence_score: ScoreExplanation
    tag_reasons: dict[str, str]


def explain_threat_score(
    indicator: ThreatIndicator,
) -> ScoreExplanation:
    """
    Explain how the threat score was calculated.
    """

    score = calculate_threat_score(
        indicator.severity,
    )

    normalized_severity = (
        indicator.severity.strip().upper()
    )

    return ScoreExplanation(
        value=score,
        reasons=[
            (
                f"{normalized_severity} severity "
                f"contributes {score}/100."
            )
        ],
    )


def explain_reputation_score(
    indicator: ThreatIndicator,
) -> ScoreExplanation:
    """
    Explain how malicious and suspicious observations
    contribute to the reputation evidence score.
    """

    score = calculate_reputation(
        indicator,
    )

    malicious_points = (
        indicator.malicious * 20
    )

    suspicious_points = (
        indicator.suspicious * 10
    )

    reasons: list[str] = []

    if indicator.malicious > 0:
        reasons.append(
            (
                f"{indicator.malicious} malicious "
                f"observations contribute "
                f"{malicious_points} points."
            )
        )

    if indicator.suspicious > 0:
        reasons.append(
            (
                f"{indicator.suspicious} suspicious "
                f"observations contribute "
                f"{suspicious_points} points."
            )
        )

    if not reasons:
        reasons.append(
            "No malicious or suspicious observations "
            "contribute to the reputation evidence score."
        )

    uncapped_score = (
        malicious_points
        + suspicious_points
    )

    if uncapped_score > 100:
        reasons.append(
            "The reputation evidence score is capped at 100."
        )

    return ScoreExplanation(
        value=score,
        reasons=reasons,
    )


def explain_confidence_score(
    threat_score: int,
    reputation_score: int,
) -> ScoreExplanation:
    """
    Explain the weighted confidence calculation.
    """

    score = calculate_confidence(
        threat_score,
        reputation_score,
    )

    weighted_threat = (
        threat_score * 0.6
    )

    weighted_reputation = (
        reputation_score * 0.4
    )

    return ScoreExplanation(
        value=score,
        reasons=[
            (
                f"60% threat score contribution: "
                f"{weighted_threat:g}."
            ),
            (
                f"40% reputation evidence contribution: "
                f"{weighted_reputation:g}."
            ),
            (
                f"Weighted result rounds to {score}/100."
            ),
        ],
    )


def explain_tags(
    indicator: ThreatIndicator,
) -> dict[str, str]:
    """
    Explain why each generated intelligence tag applies.
    """

    reasons: dict[str, str] = {}

    indicator_type = (
        indicator.type.strip().lower()
    )

    severity = (
        indicator.severity.strip().lower()
    )

    reasons[indicator_type] = (
        f"Indicator type is {indicator.type.strip().upper()}."
    )

    reasons[severity] = (
        f"Indicator severity is "
        f"{indicator.severity.strip().upper()}."
    )

    if indicator.severity.strip().upper() in {
        "HIGH",
        "CRITICAL",
    }:
        reasons["high-risk"] = (
            "Indicator severity is HIGH or CRITICAL."
        )

    if indicator.malicious > 0:
        reasons["malicious"] = (
            "Provider intelligence contains "
            "malicious observations."
        )

    if indicator.suspicious > 0:
        reasons["suspicious"] = (
            "Provider intelligence contains "
            "suspicious observations."
        )

    if indicator.reputation >= 80:
        reasons["trusted-reputation"] = (
            "Provider-reported reputation is "
            "80 or higher."
        )

    elif indicator.reputation <= 20:
        reasons["poor-reputation"] = (
            "Provider-reported reputation is "
            "20 or lower."
        )

    for tag in indicator.tags:
        normalized = tag.strip().lower()

        if normalized and normalized not in reasons:
            reasons[normalized] = (
                "Tag was supplied by threat intelligence "
                "provider or existing indicator metadata."
            )

    return dict(
        sorted(
            reasons.items(),
        )
    )


def explain_enrichment(
    indicator: ThreatIndicator,
) -> EnrichmentExplanation:
    """
    Produce a complete deterministic explanation
    of the local enrichment pipeline.
    """

    threat_score = explain_threat_score(
        indicator,
    )

    reputation_score = explain_reputation_score(
        indicator,
    )

    confidence_score = explain_confidence_score(
        threat_score.value,
        reputation_score.value,
    )

    tag_reasons = explain_tags(
        indicator,
    )

    return EnrichmentExplanation(
        threat_score=threat_score,
        reputation_score=reputation_score,
        confidence_score=confidence_score,
        tag_reasons=tag_reasons,
    )
