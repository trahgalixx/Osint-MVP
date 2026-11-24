import asyncio
import logging
from typing import List

import aiohttp

from app.core.base_module import BaseModule, Event

logger = logging.getLogger(__name__)

class CRTSHModule(BaseModule):
    name = "CRTSH"
    description = "Fetch passive subdomains from crt.sh for a given domain"
    watched_events = ["DOMAIN_NAME"]
    produced_events = ["SUBDOMAIN"]

    async def run(self, event: Event) -> List[Event]:
        domain = event.event_data
        subdomains = set()
        url = f"https://crt.sh/?q=%.{domain}&output=json"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 429:
                        logger.warning(f"Rate limit hit for {domain} on crt.sh")
                        return []  # skip this run
                    resp.raise_for_status()
                    data = await resp.json(content_type=None)
                    for entry in data:
                        # name_value can hold several names separated by newlines
                        for name in entry.get("name_value", "").splitlines():
                            name = name.strip().lower().removeprefix("*.")
                            if name != domain and name.endswith("." + domain):
                                subdomains.add(name)
        except asyncio.TimeoutError:
            logger.warning(f"Timeout fetching subdomains for {domain}")
            return []
        except aiohttp.ClientError as e:
            logger.error(f"HTTP client error while fetching subdomains for {domain}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error fetching subdomains for {domain}: {e}")
            return []

        new_events = []
        for sub in subdomains:
            new_events.append(self.create_event(
                scan_id=event.scan_id,
                event_type="SUBDOMAIN",
                event_data=sub,
                source_event_id=event.id
            ))
        return new_events

    def create_event(self, scan_id: int, event_type: str, event_data: str, source_event_id: int = None) -> Event:
        return Event(
            scan_id=scan_id,
            event_type=event_type,
            event_data=event_data,
            module_name=self.name,
            source_event_id=source_event_id
        )