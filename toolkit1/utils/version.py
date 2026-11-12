"""version.py — the toolkit's version, defined once.

The banner, --help text, and HTML report footer all read this. (The
changelog records the same "stale hardcoded version string" bug being
fixed several times; one constant makes that class of bug impossible.)
"""

__version__ = "3.10.1"
SHORT_VERSION = ".".join(__version__.split(".")[:2])     # "3.8"
