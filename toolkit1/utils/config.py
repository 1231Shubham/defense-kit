"""
config.py — JSON configuration system for the Python Security Toolkit.

Stores persistent settings (default interface, common targets, output
preferences, scan timeouts) in a JSON file so the user doesn't have to
re-enter them every session.
"""

import os
import json
from typing import Dict, Any

CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config")
CONFIG_FILE = os.path.join(CONFIG_DIR, "settings.json")

DEFAULT_CONFIG: Dict[str, Any] = {
    "default_interface": "",
    "default_gateway": "",
    "default_target": "",
    "default_ip_range": "",
    "scan_timeout": 2,
    "port_scan_threads": 100,
    "port_scan_top_ports": 100,
    "auto_log_to_db": True,
    "auto_generate_report": False,
    "report_output_dir": "reports",  # relative paths are resolved against the toolkit's own install dir, not the shell's cwd
    "report_format": "html",  # html | json | csv | sarif | pdf | all
    "operator_name": "",
    "ids_port_scan_threshold": 15,
    "ids_port_scan_window": 10.0,
    "ids_syn_flood_threshold": 60,
    "ids_syn_flood_window": 5.0,
    "enable_cve_feed": False,
    "cve_cache_ttl_hours": 24,
    "dns_resolver": "",
    "fim_watch_paths": [],  # empty = use file_integrity_monitor's built-in default list
    "auth_log_path": "",    # empty = auto-detect /var/log/auth.log or /var/log/secure
    "auth_fail_threshold": 5,
    "package_audit_max_live_lookups": 15,
    "subdomain_bruteforce_threads": 30,
    # Scheduled-scan alerting (utils/alerting.py) — every field is opt-in;
    # a channel with no URL/recipient configured is simply skipped.
    "alert_min_severity": "High",  # Critical | High | Medium | Low — the floor for "alert-worthy"
    "alert_webhook_url": "",
    "alert_slack_webhook_url": "",
    "alert_email_to": "",
    "alert_email_from": "",
    "alert_email_smtp_host": "",
    "alert_email_smtp_port": 587,
    "alert_email_use_tls": True,
    "alert_email_username": "",
    "alert_email_password": "",
    # Vulnerability Scanner: how many live-NVD-feed lookups (one per
    # distinct open-port banner) to run concurrently — see augment_with_
    # live_cve_feed()'s ThreadPoolExecutor in modules/vulnerability_scanner.py.
    "cve_feed_lookup_threads": 8,
    # Target scope guard (utils/scope.py). Entries: CIDR ("10.0.0.0/24"),
    # single IP, exact hostname ("example.com"), or subdomain wildcard
    # ("*.example.com"). Empty = unrestricted; with require_scope true an
    # empty list refuses every network target (recommended for cron runs).
    "allowed_targets": [],
    "require_scope": False,
}


# ---------------------------------------------------------------------------
# Schema validation
#
# settings.json is hand-editable, and nothing previously stopped a typo'd
# or out-of-range value (a negative thread count, "report_format": "yaml",
# a string where a module expects fim_watch_paths to be a list) from
# reaching a module and failing in a confusing way deep inside a scan
# instead of at config-load time. This is intentionally conservative: it
# only catches wrong *type*/out-of-*range* values, not "did the user mean
# this" judgment calls, and it repairs rather than crashes — a toolkit
# meant to be re-run unattended (cron, batch mode) shouldn't refuse to
# start over one bad setting.
# ---------------------------------------------------------------------------

CONFIG_SCHEMA: Dict[str, Dict[str, Any]] = {
    "scan_timeout": {"type": "number", "min": 0.1, "max": 120},
    "port_scan_threads": {"type": "int", "min": 1, "max": 1000},
    "port_scan_top_ports": {"type": "int", "min": 1, "max": 65535},
    "auto_log_to_db": {"type": "bool"},
    "auto_generate_report": {"type": "bool"},
    "report_format": {"type": "str", "choices": ("html", "json", "csv", "sarif", "pdf", "all")},
    "ids_port_scan_threshold": {"type": "int", "min": 1, "max": 10000},
    "ids_port_scan_window": {"type": "number", "min": 0.1, "max": 3600},
    "ids_syn_flood_threshold": {"type": "int", "min": 1, "max": 100000},
    "ids_syn_flood_window": {"type": "number", "min": 0.1, "max": 3600},
    "enable_cve_feed": {"type": "bool"},
    "cve_cache_ttl_hours": {"type": "int", "min": 1, "max": 24 * 30},
    "fim_watch_paths": {"type": "list"},
    "allowed_targets": {"type": "list"},
    "require_scope": {"type": "bool"},
    "auth_fail_threshold": {"type": "int", "min": 1, "max": 1000},
    "package_audit_max_live_lookups": {"type": "int", "min": 0, "max": 500},
    "subdomain_bruteforce_threads": {"type": "int", "min": 1, "max": 200},
    "alert_min_severity": {"type": "str", "choices": ("Critical", "High", "Medium", "Low")},
    "alert_email_smtp_port": {"type": "int", "min": 1, "max": 65535},
    "alert_email_use_tls": {"type": "bool"},
    "cve_feed_lookup_threads": {"type": "int", "min": 1, "max": 64},
}


def _type_ok(value: Any, kind: str) -> bool:
    if kind == "bool":
        return isinstance(value, bool)
    if kind == "int":
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if kind == "str":
        return isinstance(value, str)
    if kind == "list":
        return isinstance(value, list)
    return True


def validate_config(config: Dict[str, Any]) -> "tuple[Dict[str, Any], List[str]]":
    """Check *config* against CONFIG_SCHEMA. Returns (repaired_config,
    warnings) — any key that fails its type/range/choice check is reset
    to its DEFAULT_CONFIG value and reported in warnings; everything else
    (including keys not in the schema at all — e.g. future settings this
    version doesn't know about yet) passes through untouched."""
    repaired = dict(config)
    warnings: List[str] = []

    for key, rule in CONFIG_SCHEMA.items():
        if key not in repaired:
            continue
        value = repaired[key]
        problem = None

        if not _type_ok(value, rule["type"]):
            problem = f"expected type {rule['type']}, got {type(value).__name__}"
        elif rule.get("choices") is not None and value not in rule["choices"]:
            problem = f"must be one of {rule['choices']}"
        elif rule["type"] in ("int", "number"):
            if "min" in rule and value < rule["min"]:
                problem = f"{value} is below the minimum ({rule['min']})"
            elif "max" in rule and value > rule["max"]:
                problem = f"{value} is above the maximum ({rule['max']})"

        if problem:
            default_val = DEFAULT_CONFIG.get(key)
            warnings.append(f"{key}: {problem} — reset to default ({default_val!r})")
            repaired[key] = default_val

    return repaired, warnings


# Secrets: settings.json is plaintext on disk, so these can be supplied via
# environment variables (or .env) instead. An env value overrides the file
# for the run, is never written back to settings.json by save_config(),
# and every one of these keys is masked when settings are displayed.
SECRET_ENV_VARS: Dict[str, str] = {
    "alert_email_password": "TOOLKIT_ALERT_EMAIL_PASSWORD",
    "alert_email_username": "TOOLKIT_ALERT_EMAIL_USERNAME",
    "alert_webhook_url": "TOOLKIT_ALERT_WEBHOOK_URL",
    "alert_slack_webhook_url": "TOOLKIT_ALERT_SLACK_WEBHOOK_URL",
}


def _env_secret(key: str) -> str:
    env_name = SECRET_ENV_VARS.get(key)
    if not env_name:
        return ""
    try:
        from utils.db import _get_env   # env first, then the project's .env
        return _get_env(env_name)
    except Exception:
        return os.environ.get(env_name, "")


def mask_value(key: str, value: Any) -> str:
    """Display form of a setting: secrets are hidden (blank stays blank)."""
    if key in SECRET_ENV_VARS:
        if _env_secret(key):
            return "******** (from environment)"
        return "********" if value else ""
    return str(value)


_validation_warned_this_process = False


def load_config() -> Dict[str, Any]:
    """Load config from disk, merged over defaults, then validated against
    CONFIG_SCHEMA (invalid values are repaired in memory — see
    validate_config() — the warning is printed once per process rather
    than on every load_config() call, since main.py calls this several
    times per run)."""
    global _validation_warned_this_process
    config = dict(DEFAULT_CONFIG)
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as fh:
                user_config = json.load(fh)
            config.update(user_config)
        except (json.JSONDecodeError, OSError):
            pass

    for key in SECRET_ENV_VARS:
        env_value = _env_secret(key)
        if env_value:
            config[key] = env_value

    config, warnings = validate_config(config)
    if warnings and not _validation_warned_this_process:
        _validation_warned_this_process = True
        try:
            from utils.rich_ui import print_warning
            print_warning(f"{len(warnings)} setting(s) in config/settings.json failed "
                          f"validation and were reset to their defaults for this run:")
            for w in warnings:
                print_warning(f"  {w}")
            print_warning("Edit these in the Settings menu, or fix settings.json directly.")
        except Exception:
            pass  # validation itself must never block startup

    return config


def save_config(config: Dict[str, Any]) -> None:
    """Persist config to disk (owner-only permissions; env-supplied secrets
    are never written back — the on-disk value is kept instead)."""
    to_write = dict(config)
    if any(_env_secret(k) for k in SECRET_ENV_VARS):
        on_disk: Dict[str, Any] = {}
        try:
            with open(CONFIG_FILE, "r") as fh:
                on_disk = json.load(fh)
        except (OSError, json.JSONDecodeError):
            pass
        for key in SECRET_ENV_VARS:
            if _env_secret(key):
                to_write[key] = on_disk.get(key, DEFAULT_CONFIG.get(key, ""))

    os.makedirs(CONFIG_DIR, exist_ok=True)
    fd = os.open(CONFIG_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(to_write, fh, indent=2)
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except OSError:
        pass


def print_config(config: Dict[str, Any]) -> None:
    """Print the current configuration as a table."""
    from utils.rich_ui import get_console, RICH_AVAILABLE
    console = get_console()
    if RICH_AVAILABLE:
        from rich.table import Table
        from rich.box import ROUNDED
        table = Table(title="Current Configuration", border_style="border",
                      box=ROUNDED, header_style="primary")
        table.add_column("Setting", style="primary")
        table.add_column("Value", style="white")
        for key in sorted(config.keys()):
            table.add_row(key, mask_value(key, config[key]))
        console.print(table)
    else:
        print("\n--- Current Configuration ---")
        for key in sorted(config.keys()):
            print(f"  {key}: {mask_value(key, config[key])}")


def edit_config_interactive(config: Dict[str, Any]) -> Dict[str, Any]:
    """Interactively edit configuration values. Returns updated config."""
    print("\nEdit configuration — press Enter to keep current value.\n")
    editable = [
        ("default_interface", "Default network interface"),
        ("default_gateway", "Default gateway IP"),
        ("default_target", "Default target IP"),
        ("default_ip_range", "Default scan range (CIDR)"),
        ("scan_timeout", "Scan timeout (seconds)"),
        ("port_scan_threads", "Port scan thread count"),
        ("port_scan_top_ports", "Port scan: top-N ports"),
        ("operator_name", "Operator name"),
        ("auto_log_to_db", "Auto-log to database (true/false)"),
        ("auto_generate_report", "Auto-generate report on exit (true/false)"),
        ("report_output_dir", "Report output directory"),
        ("report_format", "Report format: html / json / csv / sarif / pdf / all"),
        ("ids_port_scan_threshold", "IDS: distinct ports that trigger a scan alert"),
        ("ids_port_scan_window", "IDS: port-scan detection window (seconds)"),
        ("ids_syn_flood_threshold", "IDS: new connections that trigger a flood alert"),
        ("ids_syn_flood_window", "IDS: flood detection window (seconds)"),
        ("enable_cve_feed", "Vulnerability Scanner: enable live NVD CVE lookups (true/false)"),
        ("cve_cache_ttl_hours", "Vulnerability Scanner: CVE cache freshness (hours)"),
        ("dns_resolver", "DNS Security Auditor: resolver IP to query (blank = auto-detect)"),
        ("auth_log_path", "Auth Log Analyzer: log file path (blank = auto-detect)"),
        ("auth_fail_threshold", "Auth Log Analyzer: failed attempts that trigger a brute-force finding"),
        ("package_audit_max_live_lookups", "Package/CVE Auditor: max live NVD lookups per run"),
        ("subdomain_bruteforce_threads", "Subdomain Mapper: DNS brute-force thread count"),
        ("cve_feed_lookup_threads", "Vulnerability Scanner: concurrent live-NVD-lookup threads"),
        ("alert_min_severity", "Scheduled scans: minimum severity that triggers an alert (Critical/High/Medium/Low)"),
        ("alert_webhook_url", "Scheduled scans: generic webhook URL (blank = disabled)"),
        ("alert_slack_webhook_url", "Scheduled scans: Slack incoming-webhook URL (blank = disabled)"),
        ("alert_email_to", "Scheduled scans: alert recipient email (blank = disabled)"),
        ("alert_email_smtp_host", "Scheduled scans: SMTP host for email alerts"),
    ]

    for key, label in editable:
        current = config.get(key, "")
        shown = mask_value(key, current)
        new_val = input(f"  {label} [{shown}]: ").strip()
        if new_val:
            # Type coercion
            if key in ("scan_timeout", "port_scan_threads", "port_scan_top_ports",
                       "ids_port_scan_threshold", "ids_syn_flood_threshold",
                       "cve_cache_ttl_hours", "auth_fail_threshold",
                       "package_audit_max_live_lookups", "subdomain_bruteforce_threads",
                       "cve_feed_lookup_threads"):
                try:
                    config[key] = int(new_val)
                except ValueError:
                    print(f"    Invalid number, keeping {current}")
            elif key in ("ids_port_scan_window", "ids_syn_flood_window"):
                try:
                    config[key] = float(new_val)
                except ValueError:
                    print(f"    Invalid number, keeping {current}")
            elif key in ("auto_log_to_db", "auto_generate_report", "enable_cve_feed"):
                config[key] = new_val.lower() in ("true", "yes", "1")
            elif key == "report_format":
                if new_val.lower() in ("html", "json", "csv", "pdf", "all"):
                    config[key] = new_val.lower()
                else:
                    print(f"    Invalid format ({new_val!r}) — must be html/json/csv/pdf/all, keeping {current}")
            else:
                config[key] = new_val

    save_config(config)
    return config
