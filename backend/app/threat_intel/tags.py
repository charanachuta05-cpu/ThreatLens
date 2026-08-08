from app.threat_intel.schemas import ThreatIndicator


def generate_tags(
    indicator: ThreatIndicator,
) -> list[str]:
    """
    Generate normalized intelligence tags.
    """

    tags: set[str] = {
        indicator.type.strip().lower(),
        indicator.severity.strip().lower(),
    }

    if indicator.severity.upper() in {
        "HIGH",
        "CRITICAL",
    }:
        tags.add("high-risk")

    if indicator.malicious > 0:
        tags.add("malicious")

    if indicator.suspicious > 0:
        tags.add("suspicious")

    if indicator.reputation >= 80:
        tags.add("trusted-reputation")

    elif indicator.reputation <= 20:
        tags.add("poor-reputation")

    for tag in indicator.tags:
        normalized = tag.strip().lower()

        if normalized:
            tags.add(normalized)

    return sorted(tags)