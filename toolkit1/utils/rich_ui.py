"""
rich_ui.py — Premium terminal UI for the Python Security Toolkit.

Provides a gradient banner with animated reveal, dashboard-style panels,
categorised module cards, status pills, spinners and prompts using the
`rich` library.  All visual output goes through this module so the
look-and-feel stays consistent across every module.

Design language
---------------
* Palette : cyan -> blue -> violet -> magenta gradient, amber accents,
            semantic green / amber / red for status.
* Shapes  : heavy frames for what matters (banner, warning), rounded
            frames for data (cards, tables, session).
* Layout  : adapts to terminal width (2-column dashboard, or stacked).
* Glyphs  : unicode icons on UTF-8 terminals, plain ASCII otherwise.
* Safe    : every function has a plain-text fallback if `rich` is missing,
            and the public function names / signatures are unchanged.

Knobs
-----
BRAND_WORDS         banner text (letters in _GLYPHS get big block art)
FEATURES / TAGLINE  banner sub-line
_CATEGORIES         how the menu groups modules (matched by name keywords)
TOOLKIT_NO_ANIM=1   env var to disable the animated banner reveal
"""

import os
import sys
import time
import shutil
import platform
import threading
from utils.version import SHORT_VERSION
from typing import List, Dict, Optional

try:
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.align import Align
    from rich.box import ROUNDED, HEAVY
    from rich.live import Live
    from rich.spinner import Spinner
    from rich.theme import Theme
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


# ---------------------------------------------------------------------------
# Brand
# ---------------------------------------------------------------------------

BRAND_WORDS = ("SENTINEL",)
TAGLINE = "NETWORK DEFENSE & AUDITING FRAMEWORK"
FEATURES = ("READ-ONLY", "SCOPE-GUARDED", "LOCAL-FIRST LOGGING")

# Gradient stops (RGB): cyan -> electric blue -> violet -> magenta
_GRADIENT = [(0, 229, 255), (41, 121, 255), (124, 77, 255), (224, 64, 251)]
_INK = "#0a0a0a"          # dark text used on coloured pills


# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------

if RICH_AVAILABLE:
    _TOOLKIT_THEME = Theme({
        "primary":   "bold #00e5ff",
        "secondary": "bold #7c4dff",
        "accent":    "bold #ffb300",
        "success":   "bold #00e676",
        "warning":   "bold #ffb300",
        "error":     "bold #ff5252",
        "danger":    "bold white on #d50000",
        "info":      "#4fc3f7",
        "muted":     "#78909c",
        "label":     "bold #eceff1",
        "value":     "#69f0ae",
        "title":     "bold #00e5ff",
        "border":    "#26c6da",
        "border.dim": "#37474f",
        "risk.low":  "bold #00e676",
        "risk.med":  "bold #ffb300",
        "risk.high": "bold #ff5252",
        "risk.info": "bold #4fc3f7",
    })
else:
    _TOOLKIT_THEME = None

_console: Optional["Console"] = None


def get_console() -> "Console":
    """Return a singleton Console instance."""
    global _console
    if _console is None:
        if RICH_AVAILABLE:
            _console = Console(theme=_TOOLKIT_THEME, highlight=False)
        else:
            _console = _FallbackConsole()
    return _console


# ---------------------------------------------------------------------------
# Fallback for when rich is not installed
# ---------------------------------------------------------------------------

class _FallbackConsole:
    """Minimal stand-in that prints plain text when rich is unavailable."""
    def print(self, *args, **kwargs):
        # Strip rich markup tags, including bare closing tags like [/]
        import re
        text = " ".join(str(a) for a in args)
        text = re.sub(r"\[/\w*\]", "", text)
        text = re.sub(r"\[\w+\]", "", text)
        print(text)

    def rule(self, *args, **kwargs):
        print("-" * 60)


# ---------------------------------------------------------------------------
# Helpers: unicode detection, symbols, gradients, pills, gauges
# ---------------------------------------------------------------------------

def _unicode_ok() -> bool:
    """True when the terminal can safely show box-drawing / icon glyphs."""
    enc = (getattr(sys.stdout, "encoding", None) or "").lower()
    return "utf" in enc


_SYMBOLS_UNICODE = {
    "ok": "✔", "err": "✖", "info": "●", "warn": "▲", "ask": "❯",
    "dot": "◆", "arrow": "▸", "bar_on": "█", "bar_off": "░", "rule": "━",
}
_SYMBOLS_ASCII = {
    "ok": "+", "err": "-", "info": "*", "warn": "!", "ask": ">",
    "dot": "*", "arrow": ">", "bar_on": "#", "bar_off": "-", "rule": "=",
}


def _sym(name: str) -> str:
    return (_SYMBOLS_UNICODE if _unicode_ok() else _SYMBOLS_ASCII)[name]


def _lerp(c1, c2, t):
    return tuple(round(a + (b - a) * t) for a, b in zip(c1, c2))


def _gradient_rgb(t: float):
    """RGB tuple at position t (0..1) along the brand gradient."""
    t = max(0.0, min(1.0, t))
    seg = len(_GRADIENT) - 1
    idx = min(int(t * seg), seg - 1)
    return _lerp(_GRADIENT[idx], _GRADIENT[idx + 1], t * seg - idx)


def _hex(rgb) -> str:
    return "#%02x%02x%02x" % tuple(rgb)


def _stop(t: float) -> str:
    """Hex colour at position t along the gradient."""
    return _hex(_gradient_rgb(t))


def _gradient_text(s: str, bold: bool = True) -> "Text":
    """One-line text with the brand gradient running left to right."""
    text = Text()
    n = max(len(s) - 1, 1)
    for i, ch in enumerate(s):
        if ch == " ":
            text.append(ch)
        else:
            text.append(ch, style=("bold " if bold else "") + _stop(i / n))
    return text


def _gradient_rule(width: int) -> "Text":
    """A horizontal ━━━━ line that fades cyan -> magenta."""
    return _gradient_text(_sym("rule") * max(width, 1), bold=False)


def _pill(label: str, bg: str, fg: str = _INK) -> "Text":
    """A solid coloured badge:  ' LABEL '."""
    return Text(f" {label} ", style=f"bold {fg} on {bg}")


def _gauge(frac: float, width: int = 16) -> "Text":
    """A horizontal bar gauge coloured green / amber / red by load."""
    frac = max(0.0, min(1.0, frac))
    on = round(frac * width)
    color = "#00e676" if frac < 0.6 else "#ffb300" if frac < 0.85 else "#ff5252"
    bar = Text()
    bar.append(_sym("bar_on") * on, style=color)
    bar.append(_sym("bar_off") * (width - on), style="#37474f")
    return bar


# ---------------------------------------------------------------------------
# Big block-letter font (6 rows)
# ---------------------------------------------------------------------------

_GLYPHS = {
    "A": [" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
    "B": ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██████╔╝", "╚═════╝ "],
    "C": [" ██████╗", "██╔════╝", "██║     ", "██║     ", "╚██████╗", " ╚═════╝"],
    "D": ["██████╗ ", "██╔══██╗", "██║  ██║", "██║  ██║", "██████╔╝", "╚═════╝ "],
    "E": ["███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"],
    "F": ["███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "██║     ", "╚═╝     "],
    "G": [" ██████╗ ", "██╔════╝ ", "██║  ███╗", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
    "H": ["██╗  ██╗", "██║  ██║", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
    "I": ["██╗", "██║", "██║", "██║", "██║", "╚═╝"],
    "L": ["██╗     ", "██║     ", "██║     ", "██║     ", "███████╗", "╚══════╝"],
    "N": ["███╗   ██╗", "████╗  ██║", "██╔██╗ ██║", "██║╚██╗██║", "██║ ╚████║", "╚═╝  ╚═══╝"],
    "O": [" ██████╗ ", "██╔═══██╗", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
    "P": ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔═══╝ ", "██║     ", "╚═╝     "],
    "R": ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"],
    "S": ["███████╗", "██╔════╝", "███████╗", "╚════██║", "███████║", "╚══════╝"],
    "T": ["████████╗", "╚══██╔══╝", "   ██║   ", "   ██║   ", "   ██║   ", "   ╚═╝   "],
    "U": ["██╗   ██╗", "██║   ██║", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
    "Y": ["██╗   ██╗", "╚██╗ ██╔╝", " ╚████╔╝ ", "  ╚██╔╝  ", "   ██║   ", "   ╚═╝   "],
}
_GLYPH_ROWS = 6


def _render_word(word: str) -> Optional[List[str]]:
    """Return the 6 text rows for `word`, or None if a letter has no glyph."""
    if any(ch not in _GLYPHS for ch in word):
        return None
    rows = [""] * _GLYPH_ROWS
    for ch in word:
        glyph = _GLYPHS[ch]
        width = max(len(r) for r in glyph)
        for i in range(_GLYPH_ROWS):
            rows[i] += glyph[i].ljust(width)
    return rows


def _shaded_block_art(rows: List[str]) -> List["Text"]:
    """Colour block art with the diagonal brand gradient; solid █ cells are
    bright and the ╔═╗ shadow cells are darkened for a 3-D look.
    Returns one Text per row (so rows can be revealed one at a time)."""
    width = max(len(r) for r in rows) or 1
    span = width + _GLYPH_ROWS * 3
    shadow = (24, 34, 54)
    lines = []
    for r, row in enumerate(rows):
        line = Text(no_wrap=True)
        for c, ch in enumerate(row):
            if ch == " ":
                line.append(" ")
                continue
            rgb = _gradient_rgb((c + r * 3) / span)
            if ch != "█":
                rgb = _lerp(rgb, shadow, 0.55)
            line.append(ch, style=("bold " if ch == "█" else "") + _hex(rgb))
        lines.append(line)
    return lines


def _banner_art(max_width: int) -> List["Text"]:
    """Pick the biggest logo layout that fits in `max_width` columns."""
    words = [_render_word(w) for w in BRAND_WORDS]
    if all(w is not None for w in words) and _unicode_ok():
        widths = [max(len(r) for r in w) for w in words]
        gap = 4
        # 1) all words side by side
        if sum(widths) + gap * (len(words) - 1) <= max_width:
            rows = [(" " * gap).join(w[i].ljust(widths[k]) for k, w in enumerate(words))
                    for i in range(_GLYPH_ROWS)]
            return _shaded_block_art(rows)
        # 2) words stacked
        if max(widths) <= max_width:
            stacked = []
            for k, w in enumerate(words):
                stacked.extend(r.ljust(max(widths)) for r in w)
                if k < len(words) - 1:
                    stacked.append("")
            return _shaded_block_art(stacked)
    # 3) compact single line for narrow terminals / unknown letters
    return [_gradient_text("  ".join(" ".join(w) for w in BRAND_WORDS))]


# ---------------------------------------------------------------------------
# Banner & warnings
# ---------------------------------------------------------------------------

def _host_ribbon() -> "Text":
    """Muted one-liner under the frame top:  host · user · time."""
    try:
        user = os.environ.get("USER") or os.environ.get("USERNAME") or "user"
    except Exception:
        user = "user"
    dot = f" {_sym('dot')} "
    ribbon = Text(justify="center", no_wrap=True, overflow="ellipsis")
    ribbon.append(f"{user}@{platform.node() or 'host'}", style="#90a4ae")
    ribbon.append(dot, style="#7c4dff")
    ribbon.append(f"{platform.system()} {platform.machine()}", style="#90a4ae")
    ribbon.append(dot, style="#7c4dff")
    ribbon.append(time.strftime("%Y-%m-%d %H:%M:%S"), style="#90a4ae")
    return ribbon


def _banner_panel(art: List["Text"], shown: int, inner: int) -> "Panel":
    """Build the banner frame with the first `shown` art rows visible."""
    rows = [(art[i] if i < shown else Text(" ")) for i in range(len(art))]
    art_width = max((len(a.plain) for a in art), default=1)
    rule_w = min(max(art_width, 24), max(inner, 24))

    chips = Text(justify="center")
    chip_colors = [_stop(0.0), _stop(0.55), _stop(1.0)]
    for i, feat in enumerate(FEATURES):
        if i:
            chips.append("  ")
        chips.append_text(_pill(feat, chip_colors[i % 3],
                                "#ffffff" if i % 3 == 1 else _INK))

    tagline = Text(justify="center")
    tagline.append_text(_gradient_rule(4))
    tagline.append("  ")
    tagline.append_text(_gradient_text(TAGLINE))
    tagline.append("  ")
    tagline.append_text(_gradient_rule(4))

    body = Group(
        _host_ribbon(),
        Text(""),
        Align.center(Group(*rows)),
        Text(""),
        Align.center(_gradient_rule(rule_w)),
        Text(""),
        tagline,
        Text(""),
        Align.center(chips),
    )
    left = Text.assemble((" ", ""), (f" {_sym('dot')} SECURITY TOOLKIT ", "bold #00e5ff"))
    return Panel(
        body, box=HEAVY, border_style="#26c6da",
        title=left, title_align="left",
        subtitle=Text.assemble(_pill(f"v{SHORT_VERSION}", "#00e5ff"), " "),
        subtitle_align="right",
        padding=(1, 2),
    )


def print_banner() -> None:
    """Print the gradient block-art banner (animated reveal on a real TTY;
    set TOOLKIT_NO_ANIM=1 to disable)."""
    console = get_console()
    if RICH_AVAILABLE:
        inner = max(console.width - 8, 20)     # panel border + padding
        art = _banner_art(inner)

        animate = (console.is_terminal and len(art) > 1
                   and not os.environ.get("TOOLKIT_NO_ANIM"))
        if animate:
            try:
                with Live(_banner_panel(art, 0, inner), console=console,
                          refresh_per_second=30, transient=False) as live:
                    for k in range(1, len(art) + 1):
                        live.update(_banner_panel(art, k, inner))
                        time.sleep(0.04)
                return
            except Exception:
                pass          # never let cosmetics break startup
        console.print(_banner_panel(art, len(art), inner))
    else:
        print(f"""
  {'   '.join(' '.join(w) for w in BRAND_WORDS)}
  {TAGLINE.title()}  v{SHORT_VERSION}
  {' | '.join(FEATURES)}
""")


def print_warning_box() -> None:
    """Print a prominent responsible-use warning."""
    console = get_console()
    if RICH_AVAILABLE:
        warn = _sym("warn")
        body = Text()
        body.append("AUTHORIZED LAB USE ONLY\n\n", style="error")
        body.append("This toolkit must only be used on networks, systems,\n", style="#ffcc80")
        body.append("and devices for which you have explicit permission.\n", style="#ffcc80")
        body.append("Unauthorized use is illegal and unethical.", style="bold #ff8a80")
        console.print(Panel(
            body,
            box=HEAVY,
            border_style="#ff5252",
            title=Text.assemble((" ", ""), _pill(f"{warn} WARNING {warn}", "#ff5252", "#ffffff")),
            title_align="left",
            padding=(1, 2),
        ))
    else:
        print("\n" + "=" * 60)
        print("  AUTHORIZED LAB USE ONLY")
        print("  This toolkit must only be used on networks, systems,")
        print("  and devices for which you have explicit permission.")
        print("=" * 60 + "\n")


# ---------------------------------------------------------------------------
# Panels & messages
# ---------------------------------------------------------------------------

def print_module_header(title: str, description: str) -> None:
    """Print a styled header panel for a module."""
    console = get_console()
    if RICH_AVAILABLE:
        content = Text()
        content.append(title + "\n", style="bold #ffffff")
        content.append(description, style="muted")
        console.print()
        console.print(Panel(
            content, box=ROUNDED, border_style="border", padding=(0, 2),
            title=Text.assemble((" ", ""), _pill("MODULE", "#7c4dff", "#ffffff")),
            title_align="left",
        ))
    else:
        print(f"\n--- {title} ---")
        print(f"    {description}\n")


def _tag(label: str, bg: str, fg: str = _INK) -> str:
    """Markup for a fixed-width status pill (6 cells)."""
    return f"[bold {fg} on {bg}] {label:^4} [/]"


def print_success(msg: str) -> None:
    get_console().print(f"{_tag('OK', '#00e676')} {msg}")


def print_error(msg: str) -> None:
    get_console().print(f"{_tag('ERR', '#ff5252', '#ffffff')} {msg}")


def print_info(msg: str) -> None:
    get_console().print(f"{_tag('INFO', '#4fc3f7')} {msg}")


def print_warning(msg: str) -> None:
    get_console().print(f"{_tag('WARN', '#ffb300')} {msg}")


def print_danger(msg: str) -> None:
    get_console().print(f"[danger] {msg} [/]")


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------

def print_scan_table(title: str, columns: List[str], rows: List[List[str]],
                     col_styles: Optional[List[str]] = None) -> None:
    """Print a styled table of scan results."""
    console = get_console()
    if RICH_AVAILABLE:
        table = Table(title=title, title_style="primary", title_justify="left",
                      border_style="border", box=ROUNDED,
                      header_style="label", show_lines=False,
                      row_styles=["", "dim"] if len(rows) > 12 else None)
        for i, col in enumerate(columns):
            style = col_styles[i] if col_styles and i < len(col_styles) else "white"
            table.add_column(col, style=style)
        for row in rows:
            table.add_row(*row)
        console.print(table)
    else:
        print(f"\n{title}")
        widths = [max(len(str(c)), max((len(str(r[i])) for r in rows), default=0))
                  for i, c in enumerate(columns)]
        header = "  ".join(c.ljust(w) for c, w in zip(columns, widths))
        print(header)
        print("-" * len(header))
        for row in rows:
            print("  ".join(str(v).ljust(w) for v, w in zip(row, widths)))


# ---------------------------------------------------------------------------
# Module menu — categorised cards
# ---------------------------------------------------------------------------

_RISK_STYLE = {"low": "risk.low", "medium": "risk.med", "high": "risk.high",
               "info": "risk.info"}

# (title, icon, name keywords).  A module lands in the first category with a
# keyword found in its lower-cased name; anything unmatched (e.g. a plugin
# you drop into modules/) goes to "MORE MODULES" automatically.
_CATEGORIES = [
    ("RECON & DISCOVERY", "◎",
     ("host discovery", "network scanner", "port scanner", "subdomain", "attack-surface")),
    ("VULNERABILITY & WEB", "◈",
     ("vulnerab", "web app", "http", "ssl", "tls", "dns")),
    ("HOST HARDENING", "▣",
     ("hardening", "firewall", "docker", "container", "package", "cve")),
    ("DETECTION & MONITORING", "◉",
     ("intrusion", "anomaly", "auth log", "integrity")),
]


def _group_modules(modules: List[Dict]):
    """Return [(title, icon, [modules])] in display order, empty ones dropped."""
    buckets = [(t, i, []) for t, i, _ in _CATEGORIES]
    other = []
    for mod in modules:
        name = str(mod.get("name", "")).lower()
        for idx, (_, _, keys) in enumerate(_CATEGORIES):
            if any(k in name for k in keys):
                buckets[idx][2].append(mod)
                break
        else:
            other.append(mod)
    if other:
        buckets.append(("MORE MODULES", "✦", other))
    return [b for b in buckets if b[2]]


def _risk_dot(level: str) -> "Text":
    style = _RISK_STYLE.get(str(level).strip().lower(), "muted")
    return Text(f"{_sym('info')} {level}", style=style)


def _entry(num, name: str, desc: str, badge_bg: str, risk: Optional[str] = None,
           badge_fg: str = _INK) -> "Group":
    """Two-line menu entry:  [ 3 ]  Name  ● Risk  /  muted description."""
    top = Text(no_wrap=True, overflow="ellipsis")
    top.append(f" {num:>2} ", style=f"bold {badge_fg} on {badge_bg}")
    top.append("  ")
    top.append(name, style="bold #ffffff")
    if risk:
        top.append("  ")
        top.append_text(_risk_dot(risk))
    if not desc:
        return Group(top)
    sub = Text(no_wrap=True, overflow="ellipsis")
    sub.append("      " + desc, style="muted")
    return Group(top, sub)


def _category_panel(title: str, icon: str, mods: List[Dict], color: str,
                    height: int) -> "Panel":
    entries = [_entry(m["id"], m["name"], m["desc"], color, m.get("risk", "Low"))
               for m in mods]
    icon = icon if _unicode_ok() else "*"
    return Panel(
        Group(*entries), box=ROUNDED, border_style=color, padding=(0, 1),
        title=Text.assemble((" ", ""), (f"{icon} {title} ", f"bold {color}")),
        title_align="left",
        subtitle=Text(f" {len(mods)} module{'s' if len(mods) != 1 else ''} ", style="muted"),
        subtitle_align="right",
        height=height,
    )


def print_module_menu(modules: List[Dict], menu_items: List[Dict] = None) -> None:
    """Print the main menu as categorised cards, plus a tools strip.

    menu_items are the non-scan tools (activity log, report, settings) —
    passed in rather than hardcoded so their displayed IDs always match
    whatever main.py actually assigned them (see main.py's _MENU_BASE).
    """
    menu_items = menu_items or []
    console = get_console()
    if RICH_AVAILABLE:
        groups = _group_modules(modules)
        n = len(groups)
        two_col = console.width >= 100
        per_row = 2 if two_col else 1

        grid = Table.grid(expand=True, padding=(0, 1, 0, 0))
        for _ in range(per_row):
            grid.add_column(ratio=1)

        for start in range(0, n, per_row):
            chunk = groups[start:start + per_row]
            height = max(len(g[2]) for g in chunk) * 2 + 2
            cells = []
            for k, (title, icon, mods) in enumerate(chunk):
                color = _stop((start + k) / max(n - 1, 1))
                cells.append(_category_panel(title, icon, mods, color, height))
            while len(cells) < per_row:
                cells.append(Text(""))
            grid.add_row(*cells)
        console.print(Text(f" {_sym('arrow')} MODULES", style="primary"))
        console.print(grid)

        # Tools strip: activity log / report / settings + exit
        tools = Table.grid(expand=True, padding=(0, 2))
        cols = len(menu_items) + 1
        for _ in range(cols):
            tools.add_column(ratio=1, no_wrap=True, overflow="ellipsis")
        cells = [_entry(it["id"], it["name"], "", "#90a4ae") for it in menu_items]
        cells.append(_entry(0, "Exit", "", "#ff5252", badge_fg="#ffffff"))
        tools.add_row(*cells)
        console.print(Panel(
            tools, box=ROUNDED, border_style="border.dim", padding=(0, 1),
            title=Text(f" {_sym('dot')} TOOLS ", style="bold #90a4ae"),
            title_align="left",
        ))

        # Legend / hint bar
        legend = Text(no_wrap=True, overflow="ellipsis")
        legend.append(" Risk  ", style="muted")
        for lvl in ("Low", "Medium", "High"):
            legend.append_text(_risk_dot(lvl))
            legend.append("   ")
        legend.append(f"{_sym('dot')}  ", style="#7c4dff")
        legend.append("type a number and press Enter", style="muted")
        console.print(legend)
    else:
        print("\n" + "=" * 55)
        print("  Available Modules")
        print("=" * 55)
        for mod in modules:
            print(f"  {mod['id']}. {mod['name']}")
            print(f"     {mod['desc']}")
        for item in menu_items:
            print(f"  {item['id']}. {item['name']}")
        print("  0.  Exit")
        print("=" * 55)


# ---------------------------------------------------------------------------
# Spinner / progress
# ---------------------------------------------------------------------------

class SpinnerContext:
    """Context manager that shows a spinner (with elapsed time) while a
    long operation runs."""
    def __init__(self, message: str):
        self.message = message
        self._stop = threading.Event()
        self._thread = None
        self._t0 = 0.0

    def _render(self):
        elapsed = time.time() - self._t0
        row = Table.grid(padding=(0, 1))
        row.add_column()
        row.add_column()
        row.add_column()
        row.add_row(self._spinner, Text(self.message, style="#cfd8dc"),
                    Text(f"{elapsed:0.1f}s", style="muted"))
        return row

    def __enter__(self):
        if RICH_AVAILABLE:
            console = get_console()
            self._t0 = time.time()
            self._spinner = Spinner("dots", style="primary")
            self._live = Live(console=console, refresh_per_second=10,
                              get_renderable=self._render)
            self._live.start()
        else:
            print(f"[*] {self.message}")
        return self

    def __exit__(self, *exc):
        if RICH_AVAILABLE:
            self._live.stop()
        return False

    def update(self, msg: str):
        self.message = msg


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------

def styled_input(prompt: str) -> str:
    """Prompt for input with a styled prefix.

    Uses a coloured chevron on a real terminal.  The ANSI codes are wrapped
    in \\001 / \\002 so readline knows they take no screen width (otherwise
    line editing and history redraw glitch).
    """
    if RICH_AVAILABLE and _unicode_ok() and sys.stdout.isatty():
        chip = f"\001\033[1;30;46m\002 {_sym('ask')} \001\033[0m\002 "
        body = f"\001\033[1m\002{prompt}\001\033[0m\002"
        return input(chip + body).strip()
    return input(f"[?] {prompt}").strip()


# ---------------------------------------------------------------------------
# Session dashboard
# ---------------------------------------------------------------------------

def _local_ip() -> Optional[str]:
    """Primary outbound IPv4 address. A UDP "connect" only picks a route --
    no packet is ever sent, so this is safe and offline-tolerant."""
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 9))  # TEST-NET-1, never actually contacted
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def _uptime_seconds() -> Optional[float]:
    """System uptime in seconds (stdlib only; None if the OS won't say)."""
    try:
        if sys.platform.startswith("linux"):
            with open("/proc/uptime") as fh:
                return float(fh.read().split()[0])
        if sys.platform == "darwin":
            import subprocess, re
            out = subprocess.check_output(["sysctl", "-n", "kern.boottime"],
                                          text=True, timeout=2)
            m = re.search(r"sec = (\d+)", out)
            return time.time() - int(m.group(1)) if m else None
        if sys.platform.startswith("win"):
            import ctypes
            return ctypes.windll.kernel32.GetTickCount64() / 1000.0
    except Exception:
        pass
    return None


def _fmt_duration(seconds: float) -> str:
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    if days:
        return f"{days}d {hours}h {minutes}m"
    return f"{hours}h {minutes}m" if hours else f"{minutes}m"


def _memory_fraction() -> Optional[float]:
    """Fraction of RAM in use. Uses psutil when installed, else /proc/meminfo."""
    try:
        import psutil  # optional
        return psutil.virtual_memory().percent / 100.0
    except Exception:
        pass
    try:
        info = {}
        with open("/proc/meminfo") as fh:
            for line in fh:
                key, _, rest = line.partition(":")
                info[key] = int(rest.split()[0])
        total, avail = info["MemTotal"], info["MemAvailable"]
        return (total - avail) / total
    except Exception:
        return None


def _host_stats() -> List[tuple]:
    """(label, renderable) rows for the HOST panel — stdlib only, and every
    probe is best-effort so a missing /proc or odd OS never breaks startup."""
    rows = [("Host", Text(platform.node() or "unknown", style="value")),
            ("Time", Text(time.strftime("%H:%M:%S  %a %d %b"), style="value"))]
    ip = _local_ip()
    if ip:
        rows.append(("IP", Text(ip, style="value")))
    up = _uptime_seconds()
    if up is not None:
        rows.append(("Uptime", Text(_fmt_duration(up), style="value")))
    try:
        load1 = os.getloadavg()[0]
        cores = os.cpu_count() or 1
        line = Text()
        line.append_text(_gauge(load1 / cores))
        line.append(f"  {load1:0.2f}", style="muted")
        rows.append(("Load", line))
    except (OSError, AttributeError):
        pass
    mem = _memory_fraction()
    if mem is not None:
        line = Text()
        line.append_text(_gauge(mem))
        line.append(f"  {int(mem * 100)}%", style="muted")
        rows.append(("Mem", line))
    try:
        du = shutil.disk_usage(os.getcwd())
        line = Text()
        line.append_text(_gauge(du.used / du.total))
        line.append(f"  {du.used * 100 // du.total}%", style="muted")
        rows.append(("Disk", line))
    except OSError:
        pass
    return rows


def print_session_info(session_info: Dict) -> None:
    """Print session details as a two-panel dashboard (SESSION + HOST)."""
    console = get_console()
    if RICH_AVAILABLE:
        icons = {"session_id": "◈", "operator": "☺", "os": "▣", "python": "λ",
                 "db_logging": "▤", "rich_ui": "✦"}
        left = Table.grid(padding=(0, 2))
        left.add_column(no_wrap=True)
        left.add_column(style="label", width=13, no_wrap=True)
        left.add_column(style="value", overflow="fold")
        for key, val in session_info.items():
            icon = icons.get(key, _SYMBOLS_UNICODE["dot"]) if _unicode_ok() else "*"
            left.add_row(f"[#7c4dff]{icon}[/]", key.replace("_", " ").title(), str(val))

        stats = _host_stats()
        right = Table.grid(padding=(0, 2))
        right.add_column(style="label", width=6, no_wrap=True)
        right.add_column(overflow="fold")
        for label, cell in stats:
            right.add_row(label, cell)

        n_rows = max(len(session_info), len(stats))
        side_by_side = console.width >= 110
        h = n_rows + 4 if side_by_side else None

        p_left = Panel(left, box=ROUNDED, border_style="border", padding=(1, 2),
                       title=Text(f" {_sym('dot')} SESSION ", style="primary"),
                       title_align="left", height=h)
        p_right = Panel(right, box=ROUNDED, border_style="#7c4dff", padding=(1, 2),
                        title=Text(f" {_sym('dot')} HOST ", style="secondary"),
                        title_align="left", height=h)
        if side_by_side:
            grid = Table.grid(expand=True, padding=(0, 1, 0, 0))
            grid.add_column(ratio=3)
            grid.add_column(ratio=2)
            grid.add_row(p_left, p_right)
            console.print(grid)
        else:
            console.print(p_left)
            console.print(p_right)
    else:
        print("\n--- Session Info ---")
        for key, val in session_info.items():
            print(f"  {key}: {val}")


def print_activity_log(entries: List[Dict]) -> None:
    """Print activity log entries as a table."""
    console = get_console()
    if RICH_AVAILABLE:
        table = Table(title="ACTIVITY LOG", title_style="primary", title_justify="left",
                      border_style="border", box=ROUNDED,
                      header_style="label", show_lines=False, expand=True)
        table.add_column("Time", style="muted", no_wrap=True)
        table.add_column("Module", style="primary")
        table.add_column("Status", no_wrap=True)
        table.add_column("Summary", style="#cfd8dc")

        for entry in entries:
            status = entry.get("status", "")
            if status == "success":
                status_cell = f"[success]{_sym('ok')} {status}[/]"
            elif status == "error":
                status_cell = f"[error]{_sym('err')} {status}[/]"
            else:
                status_cell = f"[warning]{_sym('warn')} {status}[/]"
            table.add_row(
                str(entry.get("created_at", ""))[:19],
                entry.get("module_name", ""),
                status_cell,
                entry.get("result_summary", "") or "—",
            )
        console.print(table)
    else:
        print(f"\n{'Time':<22} {'Module':<22} {'Status':<10} {'Summary'}")
        print("-" * 80)
        for entry in entries:
            print(f"{str(entry.get('created_at',''))[:19]:<22} "
                  f"{entry.get('module_name',''):<22} "
                  f"{entry.get('status',''):<10} "
                  f"{entry.get('result_summary','') or '—'}")
