"""
app/core/engine.py
ScanEngine (Orchestrator) that manages the event-driven scan lifecycle.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, List, Set, Tuple

from sqlalchemy.orm import Session

from app.core.base_module import BaseModule, Event
from app.database import Scan, ScanResult, SessionLocal

logger = logging.getLogger(__name__)


class ScanEngine:
    def __init__(self) -> None:
        self.modules: Dict[str, BaseModule] = {}
        self.event_listeners: Dict[str, List[BaseModule]] = {}

    def register_module(self, module_cls: type[BaseModule]) -> None:
        """Register a module class with the engine."""
        instance = module_cls()
        self.modules[instance.name] = instance
        for event_type in instance.watched_events:
            self.event_listeners.setdefault(event_type, []).append(instance)
        logger.info("[+] Registered module: %s (watches: %s)", instance.name, instance.watched_events)

    async def execute_scan(self, scan_id: int, target: str, target_type: str) -> None:
        """Execute a scan asynchronously using the event-driven architecture."""
        db = SessionLocal()
        try:
            scan_record = db.get(Scan, scan_id)
            if not scan_record:
                logger.error("[-] Scan ID %s not found", scan_id)
                return

            scan_record.status = "RUNNING"
            db.commit()

            seen_events: Set[Tuple[str, str]] = set()
            pending: List[Event] = []

            root_event = Event(
                scan_id=scan_id,
                event_type=target_type,
                event_data=target,
                module_name="ROOT_ENGINE",
            )
            root_event.id = self._persist_event(db, root_event)
            seen_events.add(root_event.key())
            pending.append(root_event)

            active_tasks: Set[asyncio.Task] = set()

            try:
                while pending or active_tasks:
                    # Dispatch every queued event to its listeners
                    while pending:
                        current = pending.pop(0)
                        for module in self.event_listeners.get(current.event_type, []):
                            logger.info("[+] Invoking '%s' for %s: %s",
                                        module.name, current.event_type, current.event_data)
                            active_tasks.add(asyncio.create_task(self._run_module_safe(module, current)))

                    if not active_tasks:
                        break

                    done, active_tasks = await asyncio.wait(active_tasks, return_when=asyncio.FIRST_COMPLETED)
                    for completed in done:
                        for new_event in completed.result():
                            if new_event.key() in seen_events:
                                continue
                            seen_events.add(new_event.key())
                            new_event.id = self._persist_event(db, new_event)
                            pending.append(new_event)
                            logger.info("   -> New event: %s -> %s (parent: %s)",
                                        new_event.event_type, new_event.event_data, new_event.source_event_id)

                scan_record.status = "COMPLETED"
            except Exception:
                logger.exception("[-] Scan execution failed")
                db.rollback()
                scan_record.status = "FAILED"
            scan_record.completed_at = datetime.now(timezone.utc)
            db.commit()
        finally:
            db.close()

    async def _run_module_safe(self, module: BaseModule, event: Event) -> List[Event]:
        """Run a module and return its new events; never raises."""
        try:
            return await module.run(event) or []
        except Exception:
            logger.exception("[-] Error in module '%s'", module.name)
            return []

    def _persist_event(self, db: Session, event: Event) -> int:
        """Persist an event to the database and return its ID."""
        row = ScanResult(
            scan_id=event.scan_id,
            module_name=event.module_name,
            event_type=event.event_type,
            event_data=event.event_data,
            source_event_id=event.source_event_id,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row.id

    def __repr__(self) -> str:
        return f"ScanEngine(modules={list(self.modules)})"
