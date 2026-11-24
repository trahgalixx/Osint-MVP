"""
footprint_audit.py - Digital Footprint Self-Audit

Cek seberapa terekspos identitas digital KAMU SENDIRI:
  * Keberadaan username di platform populer di Indonesia (daftar di sites.json)
  * Apakah password pernah bocor (HIBP Pwned Passwords, k-anonymity - password
    tidak pernah dikirim, hanya 5 karakter awal hash SHA-1)
  * Apakah email muncul di data breach (HIBP, butuh API key di env HIBP_API_KEY)

Intended use: audit akun milik sendiri. Jangan gunakan untuk memprofilkan orang lain.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import hashlib
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import aiohttp

# Beberapa situs menyajikan halaman berbeda untuk UA non-browser, jadi pakai UA browser.
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
TIMEOUT = aiohttp.ClientTimeout(total=20)
MAX_CONCURRENCY = 8
MAX_RETRIES = 3
NOT_FOUND_CODES = {400, 404, 410}
DEFAULT_SITES_FILE = Path(__file__).with_name("sites.json")
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


@dataclass
class CheckResult:
    source: str
    status: str  # "found" | "not_found" | "manual" | "error" | "skipped"
    category: str = ""
    url: str | None = None
    detail: dict = field(default_factory=dict)


@dataclass
class Response:
    status: int
    text: str
    final_url: str


# --------------------------------------------------------------------------- #
# HTTP helper
# --------------------------------------------------------------------------- #
async def fetch(
    session: aiohttp.ClientSession,
    sem: asyncio.Semaphore,
    url: str,
    headers: dict | None = None,
) -> Response:
    """GET dengan retry + exponential backoff."""
    delay = 1.0
    last_exc: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            async with sem, session.get(url, headers=headers) as resp:
                if resp.status in (429, 500, 502, 503, 504) and attempt < MAX_RETRIES:
                    retry_after = resp.headers.get("Retry-After", "")
                    await asyncio.sleep(float(retry_after) if retry_after.isdigit() else delay)
                    delay *= 2
                    continue
                text = await resp.text(errors="ignore")
                return Response(resp.status, text, str(resp.url))
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            last_exc = exc
            if attempt < MAX_RETRIES:
                await asyncio.sleep(delay)
                delay *= 2
    raise RuntimeError(f"Request gagal setelah {MAX_RETRIES} percobaan: {last_exc!r}")


# --------------------------------------------------------------------------- #
# Username checks (data-driven dari sites.json)
# --------------------------------------------------------------------------- #
def load_sites(path: Path = DEFAULT_SITES_FILE) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)["sites"]


def evaluate(check: dict, resp: Response) -> str:
    """Tentukan found / not_found / error dari response sesuai aturan situs."""
    kind = check["type"]
    if kind == "status":
        if resp.status == 200:
            return "found"
        return "not_found" if resp.status in NOT_FOUND_CODES else "error"
    if kind == "redirect":
        if check["marker"] in resp.final_url or resp.status in NOT_FOUND_CODES:
            return "not_found"
        return "found" if resp.status == 200 else "error"
    if resp.status != 200:
        return "not_found" if resp.status in NOT_FOUND_CODES else "error"
    if kind == "present":
        return "found" if check["marker"] in resp.text else "not_found"
    if kind == "absent":
        return "not_found" if check["marker"] in resp.text else "found"
    if kind == "json_nonempty":
        try:
            return "found" if json.loads(resp.text) else "not_found"
        except json.JSONDecodeError:
            return "error"
    raise ValueError(f"check.type tidak dikenal: {kind}")


async def check_site(session, sem, site: dict, username: str) -> CheckResult:
    u = quote(username, safe="")
    url = site["url"].format(u=u)
    profile = site.get("profile", site["url"]).format(u=u)
    base = {"source": site["name"], "category": site.get("category", "")}

    if site["check"]["type"] == "manual":
        return CheckResult(**base, status="manual", url=profile,
                           detail={"reason": "Platform memblokir cek otomatis, buka link ini sendiri"})
    try:
        resp = await fetch(session, sem, url)
    except RuntimeError as exc:
        return CheckResult(**base, status="error", detail={"error": str(exc)})

    status = evaluate(site["check"], resp)
    detail = {"http_status": resp.status} if status == "error" else {}
    return CheckResult(**base, status=status,
                       url=profile if status == "found" else None, detail=detail)


# --------------------------------------------------------------------------- #
# Breach checks (Have I Been Pwned)
# --------------------------------------------------------------------------- #
def sha1_prefix_suffix(password: str) -> tuple[str, str]:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


def count_in_range_response(body: str, suffix: str) -> int:
    for line in body.splitlines():
        hash_suffix, _, count = line.strip().partition(":")
        if hash_suffix.upper() == suffix:
            return int(count)
    return 0


async def check_password(session, sem, password: str) -> CheckResult:
    source = "HIBP Pwned Passwords"
    prefix, suffix = sha1_prefix_suffix(password)
    try:
        resp = await fetch(session, sem, f"https://api.pwnedpasswords.com/range/{prefix}",
                           headers={"Add-Padding": "true"})
    except RuntimeError as exc:
        return CheckResult(source, "error", "Keamanan", detail={"error": str(exc)})
    if resp.status != 200:
        return CheckResult(source, "error", "Keamanan", detail={"http_status": resp.status})
    count = count_in_range_response(resp.text, suffix)
    return CheckResult(source, "found" if count else "not_found", "Keamanan",
                       detail={"times_seen_in_breaches": count})


async def check_email_breaches(session, sem, email: str) -> CheckResult:
    source = "HIBP Breached Account"
    api_key = os.environ.get("HIBP_API_KEY")
    if not api_key:
        return CheckResult(source, "skipped", "Keamanan",
                           detail={"reason": "Set env HIBP_API_KEY untuk cek email"})
    try:
        resp = await fetch(
            session, sem,
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email, safe='')}"
            "?truncateResponse=false",
            headers={"hibp-api-key": api_key},
        )
    except RuntimeError as exc:
        return CheckResult(source, "error", "Keamanan", detail={"error": str(exc)})
    if resp.status == 200:
        breaches = json.loads(resp.text)
        return CheckResult(source, "found", "Keamanan", detail={
            "breaches": [
                {"name": b.get("Name"), "date": b.get("BreachDate"),
                 "data_classes": b.get("DataClasses")}
                for b in breaches
            ]
        })
    if resp.status == 404:
        return CheckResult(source, "not_found", "Keamanan")
    return CheckResult(source, "error", "Keamanan", detail={"http_status": resp.status})


# --------------------------------------------------------------------------- #
# Orchestration & report
# --------------------------------------------------------------------------- #
def exposure_summary(results: list[CheckResult]) -> dict:
    auto = [r for r in results if r.category != "Keamanan" and r.status in ("found", "not_found")]
    found = [r for r in auto if r.status == "found"]
    return {
        "platforms_checked": len(auto),
        "platforms_found": len(found),
        "manual_check_needed": sum(r.status == "manual" for r in results),
        "errors": sum(r.status == "error" for r in results),
    }


async def run_audit(username, email, password, sites) -> dict:
    sem = asyncio.Semaphore(MAX_CONCURRENCY)
    async with aiohttp.ClientSession(
        timeout=TIMEOUT,
        headers={"User-Agent": USER_AGENT, "Accept-Language": "id-ID,id;q=0.9,en;q=0.8"},
    ) as session:
        tasks = []
        if username:
            tasks += [check_site(session, sem, s, username) for s in sites]
        if email:
            tasks.append(check_email_breaches(session, sem, email))
        if password:
            tasks.append(check_password(session, sem, password))
        results = await asyncio.gather(*tasks)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": {"username": username, "email": email, "password_checked": bool(password)},
        "summary": exposure_summary(results),
        "results": [asdict(r) for r in results],
    }


def print_summary(report: dict) -> None:
    icons = {"found": "[!]", "not_found": "[ ]", "error": "[x]", "skipped": "[-]", "manual": "[?]"}
    order = {"found": 0, "manual": 1, "not_found": 2, "error": 3, "skipped": 4}
    results = sorted(report["results"], key=lambda r: (r["category"], order[r["status"]]))

    print("\n=== Digital Footprint Report ===")
    current = None
    for r in results:
        if r["category"] != current:
            current = r["category"]
            print(f"\n-- {current} --")
        line = f"{icons[r['status']]} {r['source']:<22} {r['status']:<10}"
        if r.get("url"):
            line += f" {r['url']}"
        print(line)
        if r["source"] == "HIBP Pwned Passwords" and r["status"] == "found":
            n = r["detail"]["times_seen_in_breaches"]
            print(f"      -> Password ini muncul {n}x di data bocor. Segera ganti!")
        if r["source"] == "HIBP Breached Account" and r["status"] == "found":
            for b in r["detail"]["breaches"]:
                print(f"      -> {b['name']} ({b['date']})")
        if r["status"] in ("error", "skipped") and r.get("detail"):
            print(f"      -> {r['detail']}")

    s = report["summary"]
    if s["platforms_checked"]:
        print(f"\nUsername kamu terlihat di {s['platforms_found']} dari "
              f"{s['platforms_checked']} platform yang bisa dicek otomatis.")
    if s["manual_check_needed"]:
        print(f"{s['manual_check_needed']} platform [?] perlu dicek manual lewat link di atas.")
    print("Catatan: 'found' berarti username itu ada, belum tentu akun milik kamu.")


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Audit jejak digital akun milik sendiri.")
    p.add_argument("-u", "--username", help="username kamu")
    p.add_argument("-e", "--email", help="email kamu (butuh HIBP_API_KEY)")
    p.add_argument("-p", "--check-password", action="store_true",
                   help="cek password via k-anonymity (input disembunyikan)")
    p.add_argument("-o", "--output", default="footprint_report.json",
                   help="path file laporan JSON (default: footprint_report.json)")
    p.add_argument("--sites", type=Path, default=DEFAULT_SITES_FILE,
                   help="path file daftar situs (default: sites.json)")
    args = p.parse_args(argv)
    if not (args.username or args.email or args.check_password):
        p.error("minimal isi salah satu: --username, --email, atau --check-password")
    if args.username and not USERNAME_RE.match(args.username):
        p.error("username hanya boleh huruf, angka, titik, underscore, strip (maks 64)")
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    sites = load_sites(args.sites) if args.username else []
    password = getpass.getpass("Password yang mau dicek: ") if args.check_password else None

    print("[*] Menjalankan audit...")
    report = asyncio.run(run_audit(args.username, args.email, password, sites))
    print_summary(report)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Laporan disimpan di {args.output}")
    return 0


if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    sys.exit(main())
