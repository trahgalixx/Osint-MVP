"""
app/modules/mod_langsearch.py
Search-engine OSINT via the LangSearch Web Search API (https://langsearch.com).

Use cases:
  * Digital-footprint self-audit: USERNAME / EMAIL_ADDRESS / PERSON_NAME targets
  * Organisation recon:           ORGANIZATION target (organisation domain)

Only the scan's root target is searched (no recursion into discovered entities),
which keeps API usage bounded and avoids drifting onto unrelated people.
For person targets, only URLs are kept: no e-mail / phone / address extraction.
"""

import asyncio
import logging
import os
import re
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlparse

import aiohttp

from app.core.base_module import BaseModule, Event

logger = logging.getLogger(__name__)

API_URL = "https://api.langsearch.com/v1/web-search"
RESULTS_PER_QUERY = 10
MAX_ORG_EMAILS = 25
ENV_FILE = Path(__file__).resolve().parents[2] / ".env"

# host -> platform label; a URL whose host ends with one of these is a SOCIAL_PROFILE
SOCIAL_HOSTS: Dict[str, str] = {
    "facebook.com": "Facebook", "instagram.com": "Instagram", "x.com": "X",
    "twitter.com": "X", "linkedin.com": "LinkedIn", "github.com": "GitHub",
    "gitlab.com": "GitLab", "tiktok.com": "TikTok", "youtube.com": "YouTube",
    "t.me": "Telegram", "medium.com": "Medium", "reddit.com": "Reddit",
    "threads.net": "Threads", "pinterest.com": "Pinterest", "kaskus.co.id": "Kaskus",
}


def _load_api_key() -> str:
    key = os.environ.get("LANGSEARCH_API_KEY", "")
    if not key and ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            name, sep, value = line.strip().partition("=")
            if sep and name.strip() == "LANGSEARCH_API_KEY":
                key = value.strip().strip('"').strip("'")
    return key


def _social_platform(url: str) -> str | None:
    host = (urlparse(url).hostname or "").lower().removeprefix("www.").removeprefix("m.")
    for domain, label in SOCIAL_HOSTS.items():
        if host == domain or host.endswith("." + domain):
            return label
    return None


class LangSearchModule(BaseModule):
    name = "LangSearch"
    description = "Search-engine footprint (LangSearch API) for username, email, name, or organisation"
    watched_events = ["USERNAME", "EMAIL_ADDRESS", "PERSON_NAME", "ORGANIZATION"]
    produced_events = ["WEB_MENTION", "SOCIAL_PROFILE", "EMAIL_ADDRESS"]

    def _queries(self, event: Event) -> List[str]:
        t, v = event.event_type, event.event_data
        if t == "USERNAME":
            return [f'"{v}"', f'"{v}" profile OR akun OR user']
        if t == "EMAIL_ADDRESS":
            return [f'"{v}"']
        if t == "PERSON_NAME":
            return [f'"{v}"', f'"{v}" linkedin OR github OR instagram OR facebook']
        if t == "ORGANIZATION":
            return [f'"@{v}"', f'"{v}" linkedin OR github OR instagram', f'site:{v}']
        return []

    async def _search(self, session: aiohttp.ClientSession, key: str, query: str) -> List[dict]:
        payload = {"query": query, "freshness": "noLimit", "summary": False, "count": RESULTS_PER_QUERY}
        headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        for attempt in range(3):
            async with session.post(API_URL, json=payload, headers=headers,
                                    timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 429 and attempt < 2:
                    await asyncio.sleep(2 * (attempt + 1))
                    continue
                if resp.status in (401, 403):
                    logger.error("[LangSearch] API key rejected (HTTP %s)", resp.status)
                    return []
                resp.raise_for_status()
                body = await resp.json(content_type=None)
                if body.get("code") != 200:
                    logger.warning("[LangSearch] API error for %r: %s", query, body.get("msg"))
                    return []
                return ((body.get("data") or {}).get("webPages") or {}).get("value") or []
        return []

    async def run(self, event: Event) -> List[Event]:
        # Only search the root target; discovered entities are not searched again.
        if event.source_event_id is not None:
            return []
        key = _load_api_key()
        if not key:
            logger.warning("[LangSearch] LANGSEARCH_API_KEY not set (env or .env); skipping")
            return []

        hits: Dict[str, dict] = {}
        try:
            async with aiohttp.ClientSession() as session:
                for q in self._queries(event):
                    try:
                        for item in await self._search(session, key, q):
                            url = (item.get("url") or "").strip()
                            if url and url not in hits:
                                hits[url] = item
                    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                        logger.warning("[LangSearch] query %r failed: %s", q, e)
                    await asyncio.sleep(0.5)  # be gentle with the API
        except Exception as e:
            logger.error("[LangSearch] unexpected error: %s", e)
            return []

        new_events: List[Event] = []
        org_emails: set[str] = set()
        email_re = (re.compile(r"[a-z0-9._%+-]+@" + re.escape(event.event_data), re.I)
                    if event.event_type == "ORGANIZATION" else None)

        for url, item in hits.items():
            title = (item.get("name") or "").strip()
            platform = _social_platform(url)
            if platform:
                new_events.append(self.create_event(event.scan_id, "SOCIAL_PROFILE",
                                                    f"{platform}: {url}", event.id))
            else:
                data = f"{url} | {title}" if title else url
                new_events.append(self.create_event(event.scan_id, "WEB_MENTION", data, event.id))
            if email_re:
                text = f"{title} {item.get('snippet') or ''}"
                org_emails.update(m.lower() for m in email_re.findall(text))

        for email in sorted(org_emails)[:MAX_ORG_EMAILS]:
            new_events.append(self.create_event(event.scan_id, "EMAIL_ADDRESS", email, event.id))
        return new_events
