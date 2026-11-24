"""
app/main.py
FastAPI entrypoint: web UI (dashboard + scan detail) and JSON API for the OSINT engine.
"""

import asyncio
import logging
import re
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Optional, Set

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, model_validator
from sqlalchemy import func

from app.core.engine import ScanEngine
from app.database import Scan, ScanResult, SessionLocal, init_db
from app.modules.mod_crtsh import CRTSHModule
from app.modules.mod_dns_resolve import DNSResolverModule
from app.modules.mod_ip_info import IPInfoModule
from app.modules.mod_footprint import EmailBreachModule, UsernameCheckModule
from app.modules.mod_langsearch import LangSearchModule

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

engine = ScanEngine()
engine.register_module(DNSResolverModule)
engine.register_module(CRTSHModule)
engine.register_module(IPInfoModule)
engine.register_module(LangSearchModule)
engine.register_module(UsernameCheckModule)
engine.register_module(EmailBreachModule)

# Target types that concern people/organisations and require an explicit authorisation tick
FOOTPRINT_TYPES = {"USERNAME", "EMAIL_ADDRESS", "PERSON_NAME", "ORGANIZATION"}
EMAIL_RE = re.compile(r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,63}$")
USERNAME_RE = re.compile(r"^[a-z0-9._-]{1,64}$")

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

# Keep references so background scans are not garbage-collected mid-run
_background_tasks: Set[asyncio.Task] = set()

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$")
IPV4_RE = re.compile(r"^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$")


def _mark_interrupted_scans() -> None:
    """Scans left RUNNING/PENDING by a previous process can never finish; mark them FAILED."""
    db = SessionLocal()
    try:
        stale = db.query(Scan).filter(Scan.status.in_(("RUNNING", "PENDING"))).all()
        for scan in stale:
            scan.status = "FAILED"
            scan.completed_at = datetime.now(timezone.utc)
        if stale:
            db.commit()
            logger.warning("[!] Marked %d interrupted scan(s) as FAILED", len(stale))
    finally:
        db.close()


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    _mark_interrupted_scans()
    yield
    for task in list(_background_tasks):
        task.cancel()


app = FastAPI(title="Osint MVP", description="Minimal OSINT Automation Tool", lifespan=lifespan)


# --------------------------------------------------------------------------- #
# Schemas & helpers
# --------------------------------------------------------------------------- #
class ScanRequest(BaseModel):
    target: str
    target_type: Literal[
        "DOMAIN_NAME", "IP_ADDRESS", "USERNAME", "EMAIL_ADDRESS", "PERSON_NAME", "ORGANIZATION"
    ] = "DOMAIN_NAME"
    authorized: bool = False  # user confirms they own the data / have authorisation

    @model_validator(mode="after")
    def _clean_target(self):
        v = " ".join(self.target.split())
        if self.target_type == "PERSON_NAME":
            v = v.strip()
        elif self.target_type in ("USERNAME", "EMAIL_ADDRESS"):
            v = v.lower().lstrip("@")
        else:  # DOMAIN_NAME, IP_ADDRESS, ORGANIZATION
            v = re.sub(r"^[a-z]+://", "", v.lower()).split("/")[0].rstrip(".")
        if not v:
            raise ValueError("Target must not be empty")
        self.target = v
        return self


class ScanResponse(BaseModel):
    scan_id: int
    status: str


def _iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is None:  # SQLite drops tzinfo; values are stored as UTC
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _scan_to_dict(scan: Scan, result_count: Optional[int] = None) -> dict:
    data = {
        "id": scan.id,
        "target": scan.target,
        "target_type": scan.target_type,
        "status": scan.status,
        "created_at": _iso(scan.created_at),
        "completed_at": _iso(scan.completed_at),
    }
    if result_count is not None:
        data["result_count"] = result_count
    return data


def _result_to_dict(r: ScanResult) -> dict:
    return {
        "id": r.id,
        "module": r.module_name,
        "event_type": r.event_type,
        "data": r.event_data,
        "source_event_id": r.source_event_id,
        "timestamp": _iso(r.timestamp),
    }


def _get_scan_or_404(db, scan_id: int) -> Scan:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


# --------------------------------------------------------------------------- #
# HTML pages
# --------------------------------------------------------------------------- #
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def dashboard(request: Request):
    return templates.TemplateResponse(request, "index.html", {"modules": list(engine.modules.values())})


@app.get("/scan/{scan_id}", response_class=HTMLResponse, include_in_schema=False)
async def scan_detail_page(request: Request, scan_id: int):
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if not scan:
            return templates.TemplateResponse(
                request, "not_found.html", {"scan_id": scan_id}, status_code=404
            )
        return templates.TemplateResponse(request, "scan_detail.html", {"scan": _scan_to_dict(scan)})
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# JSON API
# --------------------------------------------------------------------------- #
@app.post("/api/scans", response_model=ScanResponse)
async def start_scan(request: ScanRequest):
    if request.target_type == "DOMAIN_NAME" and not DOMAIN_RE.match(request.target):
        raise HTTPException(status_code=422, detail=f"'{request.target}' is not a valid domain name")
    if request.target_type == "IP_ADDRESS" and not IPV4_RE.match(request.target):
        raise HTTPException(status_code=422, detail=f"'{request.target}' is not a valid IPv4 address")
    if request.target_type == "ORGANIZATION" and not DOMAIN_RE.match(request.target):
        raise HTTPException(status_code=422, detail=f"'{request.target}' is not a valid organisation domain")
    if request.target_type == "EMAIL_ADDRESS" and not EMAIL_RE.match(request.target):
        raise HTTPException(status_code=422, detail=f"'{request.target}' is not a valid email address")
    if request.target_type == "USERNAME" and not USERNAME_RE.match(request.target):
        raise HTTPException(status_code=422, detail="Username may only contain letters, digits, '.', '_' and '-'")
    if request.target_type == "PERSON_NAME" and not (3 <= len(request.target) <= 100):
        raise HTTPException(status_code=422, detail="Name must be 3-100 characters")
    if request.target_type in FOOTPRINT_TYPES and not request.authorized:
        raise HTTPException(
            status_code=403,
            detail="Centang konfirmasi: data ini milik Anda sendiri, atau Anda punya otorisasi tertulis dari organisasi target.",
        )

    db = SessionLocal()
    try:
        scan = Scan(target=request.target, target_type=request.target_type, status="PENDING")
        db.add(scan)
        db.commit()
        db.refresh(scan)
        scan_id, target, target_type = scan.id, scan.target, scan.target_type
    finally:
        db.close()

    task = asyncio.create_task(engine.execute_scan(scan_id, target, target_type))
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return ScanResponse(scan_id=scan_id, status="RUNNING")


# Backwards-compatible alias for the original endpoint
app.post("/scan", response_model=ScanResponse, include_in_schema=False)(start_scan)


@app.get("/api/scans", response_model=list)
async def list_scans(limit: int = 100):
    db = SessionLocal()
    try:
        counts = (
            db.query(ScanResult.scan_id, func.count(ScanResult.id))
            .group_by(ScanResult.scan_id)
            .all()
        )
        count_map = dict(counts)
        scans = db.query(Scan).order_by(Scan.id.desc()).limit(max(1, min(limit, 500))).all()
        return [_scan_to_dict(s, count_map.get(s.id, 0)) for s in scans]
    finally:
        db.close()


@app.get("/api/scans/{scan_id}", response_model=dict)
async def get_scan(scan_id: int):
    db = SessionLocal()
    try:
        scan = _get_scan_or_404(db, scan_id)
        count = db.query(func.count(ScanResult.id)).filter(ScanResult.scan_id == scan_id).scalar()
        return _scan_to_dict(scan, count)
    finally:
        db.close()


@app.delete("/api/scans/{scan_id}", response_model=dict)
async def delete_scan(scan_id: int):
    db = SessionLocal()
    try:
        scan = _get_scan_or_404(db, scan_id)
        if scan.status in ("RUNNING", "PENDING"):
            raise HTTPException(status_code=409, detail="Cannot delete a scan that is still running")
        db.query(ScanResult).filter(ScanResult.scan_id == scan_id).delete(synchronize_session=False)
        db.delete(scan)
        db.commit()
        return {"deleted": scan_id}
    finally:
        db.close()


@app.get("/api/scans/{scan_id}/results", response_model=list)
async def get_scan_results(scan_id: int, event_type: Optional[str] = None, module: Optional[str] = None):
    db = SessionLocal()
    try:
        _get_scan_or_404(db, scan_id)
        q = db.query(ScanResult).filter(ScanResult.scan_id == scan_id)
        if event_type:
            q = q.filter(ScanResult.event_type == event_type)
        if module:
            q = q.filter(ScanResult.module_name == module)
        return [_result_to_dict(r) for r in q.order_by(ScanResult.id).all()]
    finally:
        db.close()


@app.get("/api/scans/{scan_id}/graph", response_model=dict)
async def get_scan_graph(scan_id: int):
    """Nodes = scan results, edges = source_event_id -> id (data lineage)."""
    db = SessionLocal()
    try:
        _get_scan_or_404(db, scan_id)
        rows = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).order_by(ScanResult.id).all()
        ids = {r.id for r in rows}
        nodes = [
            {
                "id": r.id,
                "label": r.event_data,
                "event_type": r.event_type,
                "module": r.module_name,
                "is_root": r.source_event_id is None,
            }
            for r in rows
        ]
        edges = [
            {"id": f"{r.source_event_id}-{r.id}", "from": r.source_event_id, "to": r.id}
            for r in rows
            if r.source_event_id is not None and r.source_event_id in ids
        ]
        return {"nodes": nodes, "edges": edges}
    finally:
        db.close()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
