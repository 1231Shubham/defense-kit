"""
module_loader.py — Plugin-style auto-discovery of scan modules.

Previously, adding a module to the toolkit meant editing a hand-maintained
MODULES list in main.py in addition to dropping a new file in modules/.
This loader removes that second step: any file directly inside modules/
that defines a MODULE_META dict and a run(config, session_id) function is
picked up automatically and added to both the interactive menu and the
CLI's --module choices.

To add a new module to the toolkit:
    1. Create modules/your_module.py
    2. Give it a MODULE_META dict (see MODULE_META_SCHEMA below) and a
       run(config, session_id=None) function for interactive mode.
    3. Optionally add cli_run(args, session_id=None) for CLI mode — if
       omitted, the module is still selectable in the interactive menu
       but won't appear as a --module CLI option.
    4. That's it. No changes to main.py are needed.

MODULE_META_SCHEMA (all keys optional except where noted):
    {
        "name": str,       # display name shown in the menu (required)
        "desc": str,       # one-line description shown in the menu
        "cli_name": str,   # value for --module <cli_name>; defaults to
                           # the file's module name if omitted
        "risk": str,       # "Low" / "Medium" / "High" — shown in the menu
        "order": int,      # sort weight for menu position (lower first);
                           # defaults to 100, so explicitly-ordered
                           # built-ins sort before undecorated additions
    }
"""

import importlib
import pkgutil
from typing import Any, Dict, List

import modules as modules_pkg


def discover_modules(quiet: bool = False) -> List[Dict[str, Any]]:
    """
    Scan the modules/ package for plugin-shaped modules and return a
    MODULES-style list of dicts, numbered and sorted for menu display.

    A module is considered plugin-shaped if it exposes both a MODULE_META
    dict and a callable run(). Modules that fail to import (e.g. because
    an optional dependency like scapy is missing) are skipped with a
    warning rather than crashing the whole toolkit.
    """
    discovered: List[Dict[str, Any]] = []

    for _finder, mod_name, is_pkg in pkgutil.iter_modules(modules_pkg.__path__):
        if is_pkg or mod_name.startswith("_"):
            continue

        try:
            mod = importlib.import_module(f"modules.{mod_name}")
        except Exception as exc:  # pragma: no cover - defensive, environment-dependent
            if not quiet:
                print(f"[!] Skipping module '{mod_name}': {exc}")
            continue

        meta = getattr(mod, "MODULE_META", None)
        run_fn = getattr(mod, "run", None)
        if not isinstance(meta, dict) or not callable(run_fn):
            continue  # not a plugin-shaped module — e.g. a shared helper file

        entry = {
            "id": None,  # assigned below, after sorting
            "name": meta.get("name", mod_name.replace("_", " ").title()),
            "desc": meta.get("desc", ""),
            "module": mod,
            "cli_name": meta.get("cli_name", mod_name),
            "risk": meta.get("risk", "Unknown"),
            "order": meta.get("order", 100),
        }
        discovered.append(entry)

    discovered.sort(key=lambda e: (e["order"], e["name"]))
    for i, entry in enumerate(discovered, start=1):
        entry["id"] = i

    return discovered
