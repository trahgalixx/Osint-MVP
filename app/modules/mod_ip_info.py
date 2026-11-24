import asyncio
import logging
from typing import List

import aiohttp

from app.core.base_module import BaseModule, Event

logger = logging.getLogger(__name__)

class IPInfoModule(BaseModule):
    name = "IPInfo"
    description = "Retrieve ASN, ISP, and geolocation info for an IP address"
    watched_events = ["IP_ADDRESS"]
    produced_events = ["ASN_INFO", "GEO_LOCATION"]

    async def run(self, event: Event) -> List[Event]:
        ip = event.event_data
        asn_info = "N/A"
        geo_location = "N/A"

        url = f"http://ip-api.com/json/{ip}?fields=status,message,as,asn,org,isp,country,region,city,lat,lon,query"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 429:
                        logger.warning(f"Rate limit for IP {ip}")
                        return []  # skip
                    resp.raise_for_status()
                    data = await resp.json()
                    if data.get("status") != "success":
                        logger.debug(f"IP lookup failed for {ip}: {data.get('message')}")
                        return []  # treat as no data

                    # Extract fields
                    asn = data.get("asn", "")
                    asn_info = f"{asn} ({data.get('org', '')})" if asn else "N/A"
                    country = data.get("country", "")
                    region = data.get("region", "")
                    city = data.get("city", "")
                    lat = data.get("lat")
                    lon = data.get("lon")
                    geo_location = f"{lat},{lon} ({city}, {region}, {country})" if lat is not None and lon is not None else "N/A"

        except asyncio.TimeoutError:
            logger.warning(f"Timeout fetching IP info for {ip}")
            return []
        except aiohttp.ClientError as e:
            logger.error(f"HTTP error fetching IP info for {ip}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error fetching IP info for {ip}: {e}")
            return []

        new_events = []
        new_events.append(self.create_event(
            scan_id=event.scan_id,
            event_type="ASN_INFO",
            event_data=asn_info,
            source_event_id=event.id
        ))
        new_events.append(self.create_event(
            scan_id=event.scan_id,
            event_type="GEO_LOCATION",
            event_data=geo_location,
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