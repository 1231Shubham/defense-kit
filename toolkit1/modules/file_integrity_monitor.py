"""
file_integrity_monitor.py — Baseline hashing + drift detection for
critical local files and directories.

New in v3.5 (batch 1). This looks at the machine the toolkit is running
on, the same way system_hardening.py does, but instead of a one-shot
posture check it establishes a *baseline* (a SHA-256 hash, size, mode,
and mtime for every file under a configurable watch-list) and, on every
later run, diffs the current filesystem state against that baseline to
surface exactly what changed: files added, removed, or modified, and
files whose permission bits loosened.

This is read-only and local-only: it never writes to a watched file,
never changes permissions, and needs no network access at all. The only
thing it writes is its own baseline snapshot (config/fim_baseline.json),
which is itself covered by the same permission-drift detection the
system_hardening module core would want to protect.

Typical use:
  1. First run (no baseline yet) — establishes and saves a baseline.
  2. Every later run — compares the current state to that baseline and
     reports drift as findings (Critical/High/Medium by change type),
     then re-saves the baseline to the new current state, exactly like
     Tripwire/AIDE's "check, then commit" workflow.

A directory in the watch-list is walked recursively but capped (see
MAX_FILES_PER_ROOT) so pointing this at something huge like "/" doesn't
turn a five-second integrity check into an hours-long filesystem crawl.
"""

import hashlib
import hmac
import os
import stat
import time
from typing import Dict, List, Optional, Tuple

from utils.rich_ui import (
    print_module_header, print_success, print_error, print_info,
    print_warning, print_danger, print_scan_table, SpinnerContext,
)
from utils import db

# Plugin metadata — picked up automatically by utils/module_loader.py.
MODULE_META = {
    "name": "File Integrity Monitor",
    "desc": "Baseline-hash critical files/dirs and alert on drift on rerun",
    "cli_name": "file_integrity_monitor",
    "risk": "Low",
    "order": 10,
    # No CLI-required args — this audits the local machine, not a target.
    # --fim-mode / --fim-paths (both optional) are read directly off args
    # by cli_run() below.
    "cli_required": [],
}

TOOLKIT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINE_PATH = os.path.join(TOOLKIT_ROOT, "config", "fim_baseline.json")

# Sensible default watch-list: high-value files an attacker or a stray
# misconfiguration would touch, kept short so the default experience is
# fast. Anything missing (e.g. non-Linux, or a minimal container) is
# silently skipped rather than reported as an error.
DEFAULT_WATCH_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/hosts",
    "/etc/crontab",
    "/etc/ssh/sshd_config",
    "/etc/ssh/sshd_config.d",
    "/etc/cron.d",
]

# A directory watch-target is walked recursively but capped at this many
# files, largest-first-come, so a runaway path can't turn a quick
# integrity check into a multi-hour crawl.
MAX_FILES_PER_ROOT = 2000
HASH_CHUNK_SIZE = 65536

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def _finding(path: str, severity: str, finding: str, remediation: str) -> Dict:
    return {"path": path, "severity": severity, "finding": finding,
            "remediation": remediation}


# ---------------------------------------------------------------------------
# Filesystem walk + hashing — pure I/O helpers, never raise.
# ---------------------------------------------------------------------------

def _hash_file(path: str) -> Optional[str]:
    """SHA-256 hex digest of *path*'s contents, or None if unreadable."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(HASH_CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
    except (FileNotFoundError, PermissionError, IsADirectoryError, OSError):
        return None
    return h.hexdigest()


def _stat_record(path: str) -> Optional[Dict]:
    try:
        st = os.stat(path)
    except (FileNotFoundError, PermissionError, OSError):
        return None
    return {
        "mode": stat.S_IMODE(st.st_mode),
        "size": st.st_size,
        "mtime": int(st.st_mtime),
    }


def expand_watch_paths(watch_paths: List[str]) -> List[str]:
    """Turn the configured watch-list (files and/or directories) into a
    flat, deduplicated list of regular files to hash. Missing paths are
    silently dropped — a watch-list is written to cover multiple distro
    layouts (e.g. both /etc/ssh/sshd_config.d and RHEL equivalents), and
    most hosts won't have every entry."""
    seen: List[str] = []
    seen_set = set()

    for root in watch_paths:
        root = os.path.expanduser((root or "").strip())
        if not root:
            continue

        if os.path.isfile(root):
            if root not in seen_set:
                seen.append(root)
                seen_set.add(root)
            continue

        if not os.path.isdir(root):
            continue  # doesn't exist on this host — skip quietly

        count_this_root = 0
        for dirpath, dirnames, filenames in os.walk(root):
            # Don't follow symlinked directories — avoids link-loops and
            # accidentally walking far outside the intended watch-list.
            dirnames[:] = [d for d in dirnames
                          if not os.path.islink(os.path.join(dirpath, d))]
            for name in filenames:
                if count_this_root >= MAX_FILES_PER_ROOT:
                    break
                full = os.path.join(dirpath, name)
                if os.path.islink(full) or not os.path.isfile(full):
                    continue
                if full not in seen_set:
                    seen.append(full)
                    seen_set.add(full)
                    count_this_root += 1
            if count_this_root >= MAX_FILES_PER_ROOT:
                break

    return seen


def build_snapshot(watch_paths: List[str]) -> Dict[str, Dict]:
    """Hash + stat every file resolved from *watch_paths*. Files that
    can't be read (permissions, race with deletion) are recorded with a
    None hash rather than dropped, so a permission-locked file still
    shows up as "present but unreadable" instead of silently vanishing
    from future diffs."""
    snapshot: Dict[str, Dict] = {}
    for path in expand_watch_paths(watch_paths):
        rec = _stat_record(path)
        if rec is None:
            continue
        rec["hash"] = _hash_file(path)
        snapshot[path] = rec
    return snapshot


# ---------------------------------------------------------------------------
# Baseline persistence
# ---------------------------------------------------------------------------

def _hmac_key() -> Optional[bytes]:
    key = os.environ.get("TOOLKIT_FIM_HMAC_KEY", "")
    return key.encode("utf-8") if key else None


def _sign(payload: Dict, key: bytes) -> str:
    import json
    body = {k: v for k, v in payload.items() if k != "hmac"}
    msg = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def load_baseline() -> Optional[Dict]:
    import json
    if not os.path.exists(BASELINE_PATH):
        return None
    try:
        with open(BASELINE_PATH, "r") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return None
    # Tamper evidence: when a key is configured, an unsigned or mismatching
    # baseline is flagged (audit() turns this into a Critical finding).
    key = _hmac_key()
    if key and isinstance(data, dict):
        stored = data.get("hmac")
        data["_tampered"] = not (isinstance(stored, str)
                                 and hmac.compare_digest(stored, _sign(data, key)))
    return data


def save_baseline(watch_paths: List[str], snapshot: Dict[str, Dict]) -> None:
    import json
    os.makedirs(os.path.dirname(BASELINE_PATH), exist_ok=True)
    payload = {
        "created_at": time.time(),
        "watch_paths": watch_paths,
        "files": snapshot,
    }
    key = _hmac_key()
    if key:
        payload["hmac"] = _sign(payload, key)
    fd = os.open(BASELINE_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(payload, fh, indent=2)
    try:
        os.chmod(BASELINE_PATH, 0o600)   # also fix a pre-existing looser file
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Diff logic — pure, fully unit-testable offline.
# ---------------------------------------------------------------------------

def diff_snapshots(baseline_files: Dict[str, Dict],
                   current_files: Dict[str, Dict]) -> List[Dict]:
    findings: List[Dict] = []
    baseline_paths = set(baseline_files)
    current_paths = set(current_files)

    for path in sorted(current_paths - baseline_paths):
        findings.append(_finding(
            path, "Medium",
            "New file appeared under a watched location since the last baseline.",
            "Confirm this file is expected (e.g. a legitimate config change) "
            "then re-run to fold it into the baseline.",
        ))

    for path in sorted(baseline_paths - current_paths):
        findings.append(_finding(
            path, "High",
            "A previously-baselined file is now missing.",
            "Confirm whether this was an intentional removal; restore from "
            "backup if not.",
        ))

    for path in sorted(baseline_paths & current_paths):
        base = baseline_files[path]
        curr = current_files[path]

        if base.get("hash") != curr.get("hash"):
            if curr.get("hash") is None:
                findings.append(_finding(
                    path, "Medium",
                    "File is no longer readable to compute a hash (permission "
                    "or ownership change) — content drift can't be confirmed.",
                    "Re-run as a user/role with read access to verify contents "
                    "are unchanged.",
                ))
            else:
                findings.append(_finding(
                    path, "Critical" if path in (
                        "/etc/passwd", "/etc/shadow", "/etc/sudoers") else "High",
                    "File contents changed since the last baseline.",
                    "Review the change (diff against backup/version control if "
                    "available) and confirm it was authorized.",
                ))
        elif base.get("mode") != curr.get("mode"):
            widened = (curr.get("mode", 0) & 0o077) > (base.get("mode", 0) & 0o077)
            findings.append(_finding(
                path,
                "Medium" if widened else "Low",
                f"Permission bits changed: {oct(base.get('mode', 0))} -> "
                f"{oct(curr.get('mode', 0))}"
                + (" (more permissive)" if widened else " (less permissive)"),
                "Confirm the new mode is intentional; restrict back down if not.",
            ))

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 5))
    return findings


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def audit(watch_paths: Optional[List[str]] = None, mode: str = "auto",
         session_id=None) -> Dict:
    """
    Run one file-integrity pass.

    mode:
      "baseline" — always (re)create the baseline from current state.
      "check"    — diff against the existing baseline; error out if
                   none exists yet.
      "auto"     — check against the existing baseline if one exists,
                   otherwise create one (first-run behavior).

    Always re-saves the baseline to the just-observed state after a
    successful check, matching AIDE/Tripwire's "report, then re-commit"
    workflow — otherwise every future run would keep re-reporting the
    same already-reviewed drift.
    """
    watch_paths = watch_paths or DEFAULT_WATCH_PATHS
    existing = load_baseline()

    if mode == "check" and existing is None:
        return {"status": "no_baseline", "findings": [],
                "watch_paths": watch_paths, "file_count": 0}

    snapshot = build_snapshot(watch_paths)

    if mode == "baseline" or existing is None:
        save_baseline(watch_paths, snapshot)
        result = {"status": "baseline_created", "findings": [],
                  "watch_paths": watch_paths, "file_count": len(snapshot)}
    else:
        findings = diff_snapshots(existing.get("files", {}), snapshot)
        if existing.get("_tampered"):
            findings.insert(0, _finding(
                BASELINE_PATH, "Critical",
                "Baseline file failed HMAC verification — it was modified or "
                "replaced outside the toolkit, so the diff below cannot be trusted.",
                "Investigate who can write config/fim_baseline.json, restore a known-good "
                "copy, and re-baseline from a trusted state."))
        save_baseline(watch_paths, snapshot)
        result = {"status": "checked", "findings": findings,
                  "watch_paths": watch_paths, "file_count": len(snapshot),
                  "baseline_age_seconds": time.time() - existing.get("created_at", time.time())}

    if session_id:
        db.log_scan_result(
            session_id=session_id,
            scan_type="file_integrity",
            target="localhost",
            extra={
                "status": result["status"],
                "file_count": result["file_count"],
                "findings": result["findings"],
            },
        )

    return result


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def print_findings(result: Dict) -> None:
    status = result["status"]

    if status == "no_baseline":
        print_error("No baseline exists yet — run in 'baseline' mode first "
                    "(or just re-run this module normally, which will "
                    "create one automatically).")
        return

    if status == "baseline_created":
        print_success(f"Baseline created/refreshed: {result['file_count']} "
                      f"file(s) hashed across {len(result['watch_paths'])} "
                      f"watched path(s).")
        return

    findings = result["findings"]
    age_hrs = result.get("baseline_age_seconds", 0) / 3600.0
    print_info(f"Compared {result['file_count']} file(s) against a baseline "
              f"~{age_hrs:.1f}h old; baseline updated to current state.")

    if not findings:
        print_success("No drift detected — every watched file matches the baseline.")
        return

    rows = [[f["path"], f["severity"], f["finding"][:70]] for f in findings]
    print_scan_table(
        "File Integrity Findings", ["Path", "Severity", "Change"], rows,
        col_styles=["accent", "warning", "white"],
    )

    counts: Dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    summary = ", ".join(f"{v} {k}" for k, v in counts.items())
    print_danger(f"{len(findings)} finding(s) — {summary}")

    print_info("\nRemediation guidance:")
    for f in findings:
        print_info(f"  [{f['path']}] {f['remediation']}")


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def run(config: Dict, session_id=None) -> None:
    """Interactive entry point used by the main menu."""
    print_module_header(
        "File Integrity Monitor",
        "Baseline-hash critical files/dirs and alert on drift on rerun",
    )

    watch_paths = config.get("fim_watch_paths") or DEFAULT_WATCH_PATHS
    existing = load_baseline()

    if existing is None:
        print_info("No baseline found — this run will create one.")
        chosen_mode = "baseline"
    else:
        age_hrs = (time.time() - existing.get("created_at", time.time())) / 3600.0
        print_info(f"Existing baseline found (~{age_hrs:.1f}h old, "
                  f"{len(existing.get('files', {}))} file(s)).")
        answer = input("[?] (c)heck against it, or (r)ebaseline from scratch? [c]: ").strip().lower()
        chosen_mode = "baseline" if answer.startswith("r") else "check"

    with SpinnerContext("Hashing watched files…"):
        result = audit(watch_paths, mode=chosen_mode, session_id=session_id)

    print_findings(result)

    if session_id:
        db.log_activity(
            session_id, "file_integrity_monitor",
            {"mode": chosen_mode, "watch_paths": watch_paths},
            status="success",
            result_summary=f"{result['status']}, {len(result['findings'])} finding(s)",
        )


def cli_run(args, session_id=None) -> None:
    """CLI entry point — dispatched by main.py's plugin loader.

    Reads two module-specific, optional flags off the shared args
    namespace (added to main.py's parser alongside this module):
      --fim-mode {auto,baseline,check}  (default: auto)
      --fim-paths "path1,path2,..."     (default: DEFAULT_WATCH_PATHS)
    """
    mode = getattr(args, "fim_mode", None) or "auto"
    raw_paths = getattr(args, "fim_paths", None)
    watch_paths = [p.strip() for p in raw_paths.split(",") if p.strip()] \
        if raw_paths else DEFAULT_WATCH_PATHS

    result = audit(watch_paths, mode=mode, session_id=session_id)
    print_findings(result)
