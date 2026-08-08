def calculate_confidence(
    threat_score: int,
    reputation_score: int,
) -> int:
    """
    Calculate confidence score.

    Version 1:
        60% threat score
        40% reputation score
    """

    confidence = (
        threat_score * 0.6
        + reputation_score * 0.4
    )

    return min(
        max(round(confidence), 0),
        100,
    )