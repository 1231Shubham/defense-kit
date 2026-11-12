"""
cve_feed.py — Optional live CVE lookups against the NIST NVD REST API.

The Vulnerability Scanner ships with a small, offline, illustrative set
of known-vulnerable banner signatures (see
modules/vulnerability_scanner.py::KNOWN_VULNERABLE_SIGNATURES). That set
is deliberately tiny and hand-maintained — fine for a classroom demo, not
a real feed.

This module adds an *optional* live layer on top: given a service banner
keyword (e.g. "Apache/2.4.49", "OpenSSH_7.4"), it queries the public NVD
CVE 2.0 API for matching CVE records and returns identification data only
(CVE ID, severity, short description) — never exploit code or automated
exploitation of any kind, consistent with the rest of this toolkit.

Design goals, matching utils/db.py's philosophy:
  - Best-effort and completely optional. Disabled by default
    (config["enable_cve_feed"] = False) since it requires outbound
    internet access and NVD rate-limits unauthenticated callers.
  - Never raises. Any network error, timeout, or malformed response
    results in an empty list — callers fall back to the offline
    signature set transparently.
  - Cached to disk (config/cve_cache.json) so repeated scans of the same
    service/version don't re-hit the API every time, and so the toolkit
    stays usable if NVD is temporarily rate-limiting you.
"""

import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

CACHE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config"
)
CACHE_FILE = os.path.join(CACHE_DIR, "cve_cache.json")

# BUGFIX (v3.7.1): lookup_cve() is now called concurrently from a
# ThreadPoolExecutor (modules/vulnerability_scanner.py's
# augment_with_live_cve_feed()). Each call used to do an unsynchronized
# read-modify-write of the whole cache file — load, add one entry, save —
# so concurrent lookups silently clobbered each other's cache entries,
# and two threads truncating/rewriting the file at once could leave
# cve_cache.json outright corrupted. This lock serializes the
# read-modify-write cycle; the network request itself (the slow part)
# still happens outside the lock, so concurrency is still doing its job.
_CACHE_LOCK = threading.Lock()

# NVD's CVSS severity bands (v3.x). Used to normalize whichever CVSS
# version a given record happens to report.
_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Unknown"]


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def _load_cache() -> Dict[str, Any]:
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, "r") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_cache(cache: Dict[str, Any]) -> None:
    # Write to a temp file and atomically rename over the real one, rather
    # than truncating CACHE_FILE in place. Callers already hold
    # _CACHE_LOCK against each other, but os.replace() also protects
    # against a reader (or another process) ever observing a
    # half-written file mid-write.
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        tmp_path = f"{CACHE_FILE}.tmp-{os.getpid()}-{threading.get_ident()}"
        with open(tmp_path, "w") as fh:
            json.dump(cache, fh, indent=2)
        os.replace(tmp_path, CACHE_FILE)
    except OSError:
        pass  # Cache writes are best-effort; a failure here shouldn't block a scan.


def _cache_is_fresh(entry: Dict[str, Any], ttl_hours: float) -> bool:
    fetched_at = entry.get("fetched_at", 0)
    return (time.time() - fetched_at) < (ttl_hours * 3600)


def clear_cache() -> None:
    """Remove the on-disk CVE cache. Exposed for Settings / troubleshooting."""
    try:
        if os.path.exists(CACHE_FILE):
            os.remove(CACHE_FILE)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# NVD response parsing
# ---------------------------------------------------------------------------

def _extract_severity(cve_item: Dict[str, Any]) -> str:
    """Pull the best available CVSS severity band out of an NVD CVE item."""
    metrics = cve_item.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            severity = data.get("baseSeverity")
            if severity:
                return severity.title()
            # CVSS v2 entries carry severity outside cvssData sometimes.
            severity = entries[0].get("baseSeverity")
            if severity:
                return severity.title()
    return "Unknown"


def _extract_description(cve_item: Dict[str, Any]) -> str:
    for desc in cve_item.get("descriptions", []):
        if desc.get("lang") == "en" and desc.get("value"):
            return desc["value"][:280]
    return "No description available."


def _parse_nvd_response(raw: Dict[str, Any], limit: int) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    for vuln in raw.get("vulnerabilities", [])[:limit]:
        cve_item = vuln.get("cve", {})
        cve_id = cve_item.get("id", "Unknown-CVE")
        findings.append({
            "cve_id": cve_id,
            "severity": _extract_severity(cve_item),
            "description": _extract_description(cve_item),
        })
    # Worst-first, same convention as the offline signature set.
    findings.sort(key=lambda f: _SEVERITY_ORDER.index(f["severity"])
                  if f["severity"] in _SEVERITY_ORDER else len(_SEVERITY_ORDER))
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def lookup_cve(keyword: str, limit: int = 3, timeout: float = 6.0,
               cache_ttl_hours: float = 24.0) -> List[Dict[str, str]]:
    """
    Look up CVEs matching *keyword* (typically a service banner such as
    "Apache/2.4.49") via the NVD API. Returns up to *limit* findings, each
    a dict with cve_id, severity, and description.

    Never raises: on any failure (network, timeout, malformed JSON,
    rate-limiting) this returns an empty list so the caller can silently
    fall back to the offline signature set.
    """
    keyword = (keyword or "").strip()
    if not keyword:
        return []

    cache_key = keyword.lower()
    with _CACHE_LOCK:
        cache = _load_cache()
        cached_entry = cache.get(cache_key)
        if cached_entry and _cache_is_fresh(cached_entry, cache_ttl_hours):
            return cached_entry.get("findings", [])[:limit]

    query = urllib.parse.urlencode({
        "keywordSearch": keyword,
        "resultsPerPage": max(limit, 5),
    })
    url = f"{NVD_API_URL}?{query}"

    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "python-security-toolkit/3.0"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
            json.JSONDecodeError, OSError, ValueError):
        # Network unavailable, rate-limited, or malformed response — fall
        # back to whatever's cached (even if stale) rather than nothing.
        if cached_entry:
            return cached_entry.get("findings", [])[:limit]
        return []
    except Exception:
        return []

    findings = _parse_nvd_response(raw, limit)

    # Reload-under-lock rather than reusing the `cache` dict read above:
    # another thread may have written its own entry to the file in the
    # meantime (this call's network request was the slow part, done
    # outside the lock), and reusing our stale in-memory copy here would
    # silently drop that thread's update when we write ours back.
    with _CACHE_LOCK:
        cache = _load_cache()
        cache[cache_key] = {"fetched_at": time.time(), "findings": findings}
        _save_cache(cache)

    return findings


def is_configured() -> bool:
    """
    The NVD keyword-search endpoint needs no API key for light use, so
    this is always True — kept as a symmetric counterpart to
    utils.db.is_available() in case an API key / rate-limit tier is added
    later.
    """
    return True
