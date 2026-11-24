"""
app/modules/mod_footprint.py
Engine modules that wrap the existing footprint_audit.py checks:
  * UsernameCheckModule: username presence on the platforms listed in sites.json
  * EmailBreachModule:   Have I Been Pwned breach lookup (needs HIBP_API_KEY)
Only the scan's root target is checked.
"""

import asyncio
import logging
import os
from pathlib import Path
from typing import List

import aiohttp

import footprint_audit as fa
from app.core.base_module import BaseModule, Event

logger = logging.getLogger(__name__)
ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


def _env(name: str) -> str:
    val = os.environ.get(name, "")
    if not val and ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            k, sep, v = line.strip().partition("=")
            if sep and k.strip() == name:
                val = v.strip().strip('"').strip("'")
    return val


def _session() -> aiohttp.ClientSession:
    return aiohttp.ClientSession(timeout=fa.TIMEOUT, headers={"User-Agent": fa.USER_AGENT})


class UsernameCheckModule(BaseModule):
    name = "UsernameCheck"
    description = "Check username presence on platforms from sites.json"
    watched_events = ["USERNAME"]
    produced_events = ["SOCIAL_PROFILE", "MANUAL_CHECK"]

    async def run(self, event: Event) -> List[Event]:
        if event.source_event_id is not None:
            return []
        try:
            sites = fa.load_sites()
            sem = asyncio.Semaphore(fa.MAX_CONCURRENCY)
            async with _session() as session:
                results = await asyncio.gather(
                    *(fa.check_site(session, sem, s, event.event_data) for s in sites))
        except Exception as e:
            logger.error("[UsernameCheck] failed: %s", e)
            return []

        out: List[Event] = []
        for r in results:
            if r.status == "found":
                out.append(self.create_event(event.scan_id, "SOCIAL_PROFILE", f"{r.source}: {r.url}", event.id))
            elif r.status == "manual":
                out.append(self.create_event(event.scan_id, "MANUAL_CHECK", f"{r.source}: {r.url}", event.id))
        return out


class EmailBreachModule(BaseModule):
    name = "EmailBreach"
    description = "Have I Been Pwned breach lookup for an email (needs HIBP_API_KEY)"
    watched_events = ["EMAIL_ADDRESS"]
    produced_events = ["BREACH_INFO"]

    async def run(self, event: Event) -> List[Event]:
        if event.source_event_id is not None:
            return []
        key = _env("HIBP_API_KEY")
        if not key:
            logger.info("[EmailBreach] HIBP_API_KEY not set; skipping")
            return []
        os.environ.setdefault("HIBP_API_KEY", key)  # footprint_audit reads it from env
        try:
            async with _session() as session:
                r = await fa.check_email_breaches(session, asyncio.Semaphore(1), event.event_data)
        except Exception as e:
            logger.error("[EmailBreach] failed: %s", e)
            return []
        if r.status != "found":
            return []
        return [
            self.create_event(event.scan_id, "BREACH_INFO",
                              f"{b['name']} ({b['date']}): {', '.join(b.get('data_classes') or [])}", event.id)
            for b in r.detail.get("breaches", [])
        ]
