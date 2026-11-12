"""
docker_auditor.py — Local Docker/container security-posture auditor.

New in v3.6. Looks at the Docker installation on the machine the toolkit
is running on (not a remote target) and flags the same category of
misconfigurations a CIS Docker Benchmark tool would: containers running
as root, containers with more host access than they need, and a daemon
that's more reachable than it should be.

Every check here is read-only: it shells out to the `docker` CLI (or
inspects a couple of well-known files) and never starts, stops, modifies,
or removes anything. If Docker isn't installed, isn't running, or the
current user can't talk to the daemon, that's reported as a single
informational finding rather than a crash — same degrade-gracefully
pattern as system_hardening.py.

Checks performed:
  1. Daemon socket exposure — is dockerd listening on a TCP port (common
     misconfig: `-H tcp://0.0.0.0:2375`, unauthenticated remote root)?
  2. Unix socket permissions — is /var/run/docker.sock world-writable?
  3. Per-container: running as root (no USER directive / explicit --user).
  4. Per-container: --privileged.
  5. Per-container: host network mode (--network host).
  6. Per-container: host PID/IPC namespace sharing (--pid host / --ipc host).
  7. Per-container: docker.sock bind-mounted *into* the container (lets a
     compromised container control the host's Docker daemon).
  8. Per-container: ports published on 0.0.0.0 rather than 127.0.0.1.
"""

import json
import shutil
import subprocess
from typing import Dict, List, Optional

from utils.rich_ui import (
    print_module_header, print_success, print_error, print_info,
    print_warning, print_danger, print_scan_table, SpinnerContext,
)
from utils import db

# Plugin metadata — picked up automatically by utils/module_loader.py.
MODULE_META = {
    "name": "Docker/Container Auditor",
    "desc": "Local, read-only checks for risky Docker daemon/container configuration",
    "cli_name": "docker_auditor",
    "risk": "Medium",
    "order": 13,
    # Audits the local Docker install, not a remote target — no CLI flags needed.
    "cli_required": [],
}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
_TIMEOUT = 8


def _finding(component: str, severity: str, finding: str, remediation: str) -> Dict:
    return {"component": component, "severity": severity, "finding": finding,
            "remediation": remediation}


def _run(cmd: List[str]) -> Optional[str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=_TIMEOUT)
        if result.returncode != 0:
            return None
        return result.stdout
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return None


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _daemon_reachable() -> bool:
    return _run(["docker", "info", "--format", "{{.ServerVersion}}"]) is not None


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_socket_permissions() -> List[Dict]:
    import os
    import stat
    sock_path = "/var/run/docker.sock"
    findings: List[Dict] = []
    try:
        mode = stat.S_IMODE(os.stat(sock_path).st_mode)
    except (FileNotFoundError, PermissionError, OSError):
        return findings
    if mode & 0o002:
        findings.append(_finding(
            "Daemon Socket", "Critical",
            f"{sock_path} is world-writable (mode {oct(mode)}) — any local user "
            f"can drive the Docker daemon, which is equivalent to root on this host.",
            f"chmod 660 {sock_path} and restrict membership of the docker group; "
            f"never chmod 666 the socket to work around a permissions issue.",
        ))
    return findings


def check_daemon_tcp_exposure() -> List[Dict]:
    """dockerd listening on a TCP port with no TLS is unauthenticated
    remote root on this host. Checked via the daemon config file and a
    local process/socket listing rather than probing the network."""
    findings: List[Dict] = []
    for cfg_path in ("/etc/docker/daemon.json",):
        try:
            with open(cfg_path, "r") as fh:
                cfg = json.load(fh)
        except (FileNotFoundError, PermissionError, OSError, json.JSONDecodeError):
            continue
        hosts = cfg.get("hosts", [])
        for h in hosts:
            if isinstance(h, str) and h.startswith("tcp://"):
                tls = cfg.get("tls", False) or cfg.get("tlsverify", False)
                sev = "Low" if tls else "Critical"
                findings.append(_finding(
                    "Daemon Socket", sev,
                    f"dockerd is configured to listen on {h}"
                    + ("" if tls else " with no TLS configured"),
                    "Remove the tcp:// host binding unless remote API access is "
                    "explicitly required, and if it is, enable --tlsverify with "
                    "client certificate authentication.",
                ))

    # Fallback: check for a listening process on the conventional Docker
    # API port even when daemon.json wasn't readable/present.
    ss_out = _run(["ss", "-tlnp"]) or _run(["netstat", "-tlnp"])
    if ss_out and (":2375" in ss_out or ":2376" in ss_out):
        port = "2375" if ":2375" in ss_out else "2376"
        sev = "Critical" if port == "2375" else "Low"
        findings.append(_finding(
            "Daemon Socket", sev,
            f"Something is listening on the conventional Docker API port {port}"
            + (" (unencrypted)" if port == "2375" else " (TLS port, verify certs are enforced)"),
            "Confirm this is intentional and firewalled to trusted hosts only, "
            "or disable the TCP listener entirely.",
        ))
    return findings


def _list_containers() -> Optional[List[str]]:
    out = _run(["docker", "ps", "-aq"])
    if out is None:
        return None
    return [line.strip() for line in out.splitlines() if line.strip()]


def _inspect(container_id: str) -> Optional[Dict]:
    out = _run(["docker", "inspect", container_id])
    if not out:
        return None
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return None
    return data[0] if data else None


def check_containers() -> List[Dict]:
    findings: List[Dict] = []
    ids = _list_containers()
    if not ids:
        return findings

    for cid in ids:
        info = _inspect(cid)
        if not info:
            continue
        name = (info.get("Name") or cid)[:64].lstrip("/")
        config = info.get("Config", {}) or {}
        host_config = info.get("HostConfig", {}) or {}

        user = (config.get("User") or "").strip()
        if not user or user in ("0", "root", "0:0"):
            findings.append(_finding(
                name, "Medium",
                "Container runs as root (no non-root USER set) — a container "
                "compromise gets root inside the container by default.",
                "Add a USER directive to the image (or --user uid:gid at run "
                "time) so the container process runs unprivileged.",
            ))

        if host_config.get("Privileged"):
            findings.append(_finding(
                name, "Critical",
                "Container is running with --privileged — it has essentially "
                "unrestricted access to the host's devices and kernel capabilities.",
                "Remove --privileged and grant only the specific --cap-add "
                "capabilities the workload actually needs.",
            ))

        net_mode = (host_config.get("NetworkMode") or "").lower()
        if net_mode == "host":
            findings.append(_finding(
                name, "High",
                "Container uses host network mode (--network host) — it shares "
                "the host's network stack and bypasses container network isolation.",
                "Use bridge networking with explicit -p port publishing instead, "
                "unless host networking is a hard requirement.",
            ))

        pid_mode = (host_config.get("PidMode") or "").lower()
        if pid_mode == "host":
            findings.append(_finding(
                name, "High",
                "Container shares the host PID namespace (--pid host) — "
                "processes inside the container can see and signal host processes.",
                "Remove --pid host unless the container specifically needs to "
                "observe host processes (e.g. a monitoring agent).",
            ))
        ipc_mode = (host_config.get("IpcMode") or "").lower()
        if ipc_mode == "host":
            findings.append(_finding(
                name, "Medium",
                "Container shares the host IPC namespace (--ipc host).",
                "Remove --ipc host unless shared memory with the host is "
                "specifically required.",
            ))

        for mount in info.get("Mounts", []) or []:
            src = mount.get("Source", "")
            if src in ("/var/run/docker.sock", "/run/docker.sock"):
                findings.append(_finding(
                    name, "Critical",
                    "The Docker socket is bind-mounted into this container — a "
                    "compromise of the container is equivalent to root on the host "
                    "(it can drive the daemon to launch a privileged sibling container).",
                    "Avoid mounting docker.sock into containers; if Docker-in-Docker "
                    "is required, use a properly scoped alternative (e.g. rootless "
                    "DinD or a socket proxy that allow-lists the API surface).",
                ))

        for _container_port, bindings in (host_config.get("PortBindings") or {}).items():
            for b in bindings or []:
                host_ip = b.get("HostIp") or "0.0.0.0"
                if host_ip in ("0.0.0.0", "", "::"):
                    findings.append(_finding(
                        name, "Low",
                        f"Port {_container_port} is published on all interfaces "
                        f"(0.0.0.0) rather than bound to localhost.",
                        "Bind to 127.0.0.1 (e.g. -p 127.0.0.1:8080:80) unless the "
                        "service is meant to be reachable from other hosts, and "
                        "rely on the host firewall for anything that must stay internal.",
                    ))
    return findings


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def audit(session_id=None) -> List[Dict]:
    if not _docker_available():
        findings = [_finding(
            "Platform", "Info",
            "Docker CLI not found on PATH — Docker is not installed, or not "
            "installed for this user. No checks were run.",
            "N/A",
        )]
    elif not _daemon_reachable():
        findings = [_finding(
            "Platform", "Info",
            "Docker CLI is present but the daemon isn't reachable (not running, "
            "or the current user isn't in the docker group). No checks were run.",
            "Start the Docker service, or re-run as a user with daemon access, "
            "for a complete audit.",
        )]
    else:
        findings = []
        findings += check_socket_permissions()
        findings += check_daemon_tcp_exposure()
        findings += check_containers()

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 5))

    if session_id:
        db.log_scan_result(
            session_id=session_id,
            scan_type="docker_audit",
            target="local-docker",
            extra={
                "findings": findings,
                "severity_counts": {
                    s: sum(1 for f in findings if f["severity"] == s)
                    for s in ("Critical", "High", "Medium", "Low", "Info")
                },
            },
        )

    return findings


def print_findings(findings: List[Dict]) -> None:
    if not findings:
        print_success("No Docker findings — daemon and containers (if any) look clean.")
        return

    rows = [[f["component"], f["severity"], f["finding"][:70]] for f in findings]
    print_scan_table(
        "Docker Audit Findings",
        ["Component", "Severity", "Finding"],
        rows,
        col_styles=["accent", "warning", "white"],
    )

    counts: Dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    summary = ", ".join(f"{v} {k}" for k, v in counts.items())
    real_findings = [f for f in findings if f["severity"] != "Info"]
    if real_findings:
        print_danger(f"{len(findings)} finding(s) — {summary}")
    else:
        print_info(f"{len(findings)} informational note(s) — {summary}")

    print_info("\nRemediation guidance:")
    for f in findings:
        if f["remediation"] != "N/A":
            print_info(f"  [{f['component']}] {f['remediation']}")


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def run(config: Dict, session_id=None) -> None:
    """Interactive entry point used by the main menu."""
    print_module_header(
        "Docker/Container Auditor",
        "Local, read-only checks for risky Docker daemon/container configuration",
    )
    if not _docker_available():
        print_warning("Docker CLI not found — nothing to audit on this host.")

    with SpinnerContext("Auditing local Docker daemon and containers…"):
        findings = audit(session_id=session_id)

    print_findings(findings)

    if session_id:
        top_sev = findings[0]["severity"] if findings else "None"
        db.log_activity(
            session_id, "docker_auditor", {},
            status="success",
            result_summary=f"{len(findings)} finding(s), highest severity: {top_sev}",
        )


def cli_run(args, session_id=None) -> None:
    """CLI entry point — audits the local machine, no target-specific flags."""
    findings = audit(session_id=session_id)
    print_findings(findings)
