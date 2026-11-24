"""
app/core/base_module.py
Base module definitions for OSINT modules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Tuple


@dataclass
class Event:
    scan_id: int
    event_type: str
    event_data: str
    module_name: str
    source_event_id: Optional[int] = None
    id: Optional[int] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def key(self) -> Tuple[str, str]:
        """Identity used by the engine to skip duplicate events."""
        return (self.event_type, self.event_data)


class BaseModule:
    """Abstract base class for all OSINT modules."""

    name: str = "BaseModule"
    description: str = "Base OSINT Module"
    author: str = "Anonymous"

    # Events that this module watches (input events)
    watched_events: List[str] = []
    # Events that this module produces (output events)
    produced_events: List[str] = []

    def create_event(self, scan_id: int, event_type: str, event_data: str,
                     source_event_id: Optional[int] = None) -> Event:
        return Event(
            scan_id=scan_id,
            event_type=event_type,
            event_data=event_data,
            module_name=self.name,
            source_event_id=source_event_id,
        )

    async def run(self, event: Event) -> List[Event]:
        raise NotImplementedError("Subclasses must implement 'run' method")
