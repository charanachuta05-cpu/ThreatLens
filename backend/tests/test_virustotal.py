import asyncio

from app.core.config import settings
from app.threat_intel.providers.virustotal import VirusTotalProvider


async def main():
    provider = VirusTotalProvider(
        settings.VIRUSTOTAL_API_KEY
    )

    report = await provider.get_ip_report("8.8.8.8")

    print(report)


if __name__ == "__main__":
    asyncio.run(main())