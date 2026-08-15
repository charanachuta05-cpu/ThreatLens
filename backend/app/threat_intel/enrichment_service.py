import logging

from app.threat_intel.schemas import ThreatIndicator


logger = logging.getLogger(__name__)


SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _highest_severity(
    original: str,
    enriched: str,
) -> str:
    """
    Return the strongest severity between
    the original indicator and provider result.

    Provider enrichment must never downgrade
    an existing threat severity.
    """

    original_normalized = str(original).strip().upper()
    enriched_normalized = str(enriched).strip().upper()

    original_rank = SEVERITY_RANK.get(
        original_normalized,
        1,
    )

    enriched_rank = SEVERITY_RANK.get(
        enriched_normalized,
        1,
    )

    if enriched_rank > original_rank:
        return enriched_normalized

    return original_normalized


def _merge_indicator(
    original: ThreatIndicator,
    enriched: ThreatIndicator,
    provider_name: str,
) -> ThreatIndicator:
    """
    Merge provider enrichment into the original
    normalized indicator.

    Security-sensitive fields such as type and value
    are protected from unsafe provider changes.

    Provider-controlled intelligence fields such as
    source, severity and tags are accepted when valid.

    The provider name is used as the source fallback
    when the provider does not return a usable source.
    """

    original_tags = getattr(
        original,
        "tags",
        [],
    ) or []

    enriched_tags = getattr(
        enriched,
        "tags",
        [],
    ) or []

    merged_tags = list(
        dict.fromkeys(
            [
                *original_tags,
                *enriched_tags,
            ]
        )
    )

    enriched_source = getattr(
        enriched,
        "source",
        None,
    )

    if (
        isinstance(enriched_source, str)
        and enriched_source.strip()
    ):
        source = enriched_source.strip()
    else:
        source = provider_name

    return enriched.model_copy(
        update={
            # Never allow a provider to replace
            # the original IOC identity.
            "value": original.value,
            "type": original.type,

            # Provider enrichment must never
            # downgrade existing severity.
            "severity": _highest_severity(
                original.severity,
                enriched.severity,
            ),

            # The provider is responsible for
            # the enrichment result.
            "source": source,

            # Preserve and combine tags.
            "tags": merged_tags,

            # Preserve existing reputation intelligence
            # and extend it with provider observations.
            "malicious": (
                original.malicious
                + enriched.malicious
            ),
            "suspicious": (
                original.suspicious
                + enriched.suspicious
            ),
            "harmless": (
                original.harmless
                + enriched.harmless
            ),
        }
    )



async def enrich_with_providers(
    indicator: ThreatIndicator,
    providers,
) -> ThreatIndicator:
    """
    Enrich an indicator using all registered
    threat intelligence providers.

    Provider failures are isolated so that
    one unavailable provider does not stop
    the remaining providers.

    Provider enrichment may enhance the IOC,
    but it must never downgrade its existing
    severity or replace its identity.
    """

    indicator_type = indicator.type.strip().upper()
    value = indicator.value.strip()

    enriched_indicator = indicator

    for provider in providers:

        provider_name = getattr(
            provider,
            "provider_name",
            provider.__class__.__name__,
        )

        try:
            get_indicator_report = getattr(
                provider,
                "get_indicator_report",
                None,
            )

            if get_indicator_report is None:
                logger.warning(
                    "%s does not support IOC lookup.",
                    provider_name,
                )
                continue

            result = await get_indicator_report(
                indicator_type,
                value,
            )

            if result is None:
                logger.warning(
                    "%s returned no enrichment "
                    "result for %s.",
                    provider_name,
                    value,
                )
                continue

            if not isinstance(
                result,
                ThreatIndicator,
            ):
                logger.warning(
                    "%s returned invalid enrichment "
                    "result for %s.",
                    provider_name,
                    value,
                )
                continue

            logger.info(
                "%s enriched indicator %s.",
                provider_name,
                value,
            )

            enriched_indicator = _merge_indicator(
                original=enriched_indicator,
                enriched=result,
                provider_name=provider_name,
            )

        except Exception as exc:
            logger.exception(
                "%s enrichment failed for %s: %s",
                provider_name,
                value,
                exc,
            )

    if enriched_indicator is indicator:
        logger.warning(
            "No provider could enrich indicator %s. "
            "Returning original indicator.",
            value,
        )

    return enriched_indicator
