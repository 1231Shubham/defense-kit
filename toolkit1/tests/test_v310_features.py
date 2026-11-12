"""Tests for v3.10: pinned resolution, --fail-on gate, finding history, DB migrations."""
import os, socket, sqlite3, sys, tempfile, threading, unittest
from datetime import date
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import gate, scope
from utils.findings import iter_findings, normalize_severity
from utils.pinning import pinned_resolution
from utils.trend import compute_history


def sr(target, *findings, scan_type="ssl_auditor"):
    return {"scan_type": scan_type, "target": target,
            "extra": {"findings": [{"severity": s, "finding": t} for s, t in findings]}}


class Pinning(unittest.TestCase):
    def test_check_pinned_resolves_once_and_returns_ips(self):
        calls = []
        def resolver(h):
            calls.append(h); return ["10.0.0.5"]
        cfg = {"allowed_targets": ["10.0.0.0/24"]}
        ok, _, pins = scope.check_pinned("app.example.com", cfg, resolver=resolver)
        self.assertTrue(ok)
        self.assertEqual(pins, {"app.example.com": ["10.0.0.5"]})
        self.assertEqual(len(calls), 1)             # no second lookup to rebind against

    def test_rebinding_resolver_cannot_flip_after_check(self):
        answers = iter([["10.0.0.5"], ["8.8.8.8"]])
        ok, _, pins = scope.check_pinned("a.example.com", {"allowed_targets": ["10.0.0.0/24"]},
                                         resolver=lambda h: next(answers))
        self.assertTrue(ok)
        self.assertEqual(pins["a.example.com"], ["10.0.0.5"])

    def test_out_of_scope_returns_no_pins(self):
        ok, reason, pins = scope.check_pinned("a.example.com", {"allowed_targets": ["10.0.0.0/24"]},
                                              resolver=lambda h: ["8.8.8.8"])
        self.assertFalse(ok); self.assertEqual(pins, {}); self.assertIn("outside", reason)

    def test_ip_and_unscoped_pin_nothing(self):
        self.assertEqual(scope.check_pinned("10.0.0.5", {"allowed_targets": ["10.0.0.0/24"]})[2], {})
        self.assertEqual(scope.check_pinned("example.com", {})[2], {})

    def test_pinned_connection_goes_to_pinned_ip(self):
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        port = srv.getsockname()[1]
        t = threading.Thread(target=lambda: srv.accept()[0].close(), daemon=True); t.start()
        with pinned_resolution({"pinned.invalid": ["127.0.0.1"]}):
            socket.create_connection(("pinned.invalid", port), timeout=3).close()
        t.join(3); srv.close()

    def test_restored_after_context_and_unlisted_hosts_pass_through(self):
        orig = socket.getaddrinfo
        with pinned_resolution({"x.invalid": ["127.0.0.1"]}):
            self.assertIsNot(socket.getaddrinfo, orig)
            self.assertTrue(socket.getaddrinfo("localhost", 80))   # not pinned -> real resolver
        self.assertIs(socket.getaddrinfo, orig)

    def test_family_filter(self):
        with pinned_resolution({"v4.invalid": ["127.0.0.1"]}):
            with self.assertRaises(socket.gaierror):
                socket.getaddrinfo("v4.invalid", 80, socket.AF_INET6)


class Gate(unittest.TestCase):
    R = [sr("a", ("High", "TLS 1.0"), ("Low", "no hsts"))]

    def test_threshold(self):
        self.assertEqual(len(gate.blocking_findings(self.R, "High")), 1)
        self.assertEqual(len(gate.blocking_findings(self.R, "Critical")), 0)
        self.assertEqual(len(gate.blocking_findings(self.R, "Low")), 2)
        self.assertEqual(gate.blocking_findings(self.R, None), [])

    def test_suppression_unblocks(self):
        e = [{"match": "tls 1.0", "expires": "2030-01-01"}]
        self.assertEqual(gate.blocking_findings(self.R, "High", e, date(2026, 1, 1)), [])
        self.assertEqual(len(gate.blocking_findings(self.R, "High", e, date(2031, 1, 1))), 1)

    def test_exit_code_distinct_from_error(self):
        self.assertEqual(gate.EXIT_FINDINGS, 2)

    def test_cli_flag_registered(self):
        import main
        a = main.build_parser().parse_args(["--module", "ssl_auditor", "--fail-on", "High"])
        self.assertEqual(a.fail_on, "High")


class Findings(unittest.TestCase):
    def test_junk_tolerated_and_severity_normalized(self):
        self.assertEqual(iter_findings([None, {"extra": 3}, {"extra": {"findings": [None]}}]), [])
        self.assertEqual(normalize_severity("high"), "High")
        self.assertEqual(normalize_severity("bogus"), "Info")


class Trend(unittest.TestCase):
    def test_open_resolved_and_age(self):
        s1 = ("s1", "2026-10-01T00:00:00+00:00", [sr("h", ("High", "A"), ("Low", "B"))])
        s2 = ("s2", "2026-10-11T00:00:00+00:00", [sr("h", ("High", "A"))])
        s3 = ("s3", "2026-10-21T00:00:00+00:00", [sr("h", ("High", "A"))])
        h = compute_history([s3, s1, s2])                 # order-independent
        self.assertEqual([f["title"] for f in h["open"]], ["A"])
        self.assertEqual(h["open"][0]["age_days"], 20)
        self.assertEqual(h["open"][0]["sessions_seen"], 3)
        self.assertEqual([f["title"] for f in h["resolved"]], ["B"])
        self.assertEqual(h["resolved"][0]["days_to_resolve"], 0)

    def test_unscanned_target_not_marked_resolved(self):
        s1 = ("s1", "2026-10-01T00:00:00+00:00", [sr("h1", ("High", "A"))])
        s2 = ("s2", "2026-10-02T00:00:00+00:00", [sr("h2", ("Low", "B"))])
        h = compute_history([s1, s2])
        self.assertIn("A", [f["title"] for f in h["open"]])   # h1 simply wasn't rescanned

    def test_empty(self):
        self.assertEqual(compute_history([]), {"open": [], "resolved": [], "sessions": 0})


class Migrations(unittest.TestCase):
    def test_versioned_and_idempotent(self):
        from utils import db
        conn = sqlite3.connect(":memory:")
        conn.executescript(db._SCHEMA)
        db._migrate(conn); db._migrate(conn)
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], len(db._MIGRATIONS))
        names = {r[1] for r in conn.execute("PRAGMA index_list(scan_results)")}
        self.assertIn("idx_scan_type_target", names)

    def test_connect_upgrades_existing_db(self):
        from utils import db
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(db, "LOG_DIR", d):
                conn = db._connect(); self.assertIsNotNone(conn)
                self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], len(db._MIGRATIONS))
                conn.close()


class StableIds(unittest.TestCase):
    def rid(self, text, st="x"):
        from utils.sarif import rule_id
        return rule_id(st, {"finding": text})

    def test_counts_do_not_change_identity(self):
        a = self.rid("6 failed password attempt(s) from 203.0.113.9 against 1 known username(s) (root)")
        b = self.rid("7 failed password attempt(s) from 203.0.113.9 against 2 known username(s) (root)")
        self.assertEqual(a, b)

    def test_ip_port_version_do_change_identity(self):
        self.assertNotEqual(self.rid("3 failed attempts from 203.0.113.9"),
                            self.rid("3 failed attempts from 203.0.113.10"))
        self.assertNotEqual(self.rid("Port 8099 exposes admin"), self.rid("Port 8100 exposes admin"))
        self.assertNotEqual(self.rid("TLS 1.0 enabled"), self.rid("TLS 1.1 enabled"))

    def test_explicit_id_wins(self):
        from utils.sarif import rule_id
        self.assertEqual(rule_id("x", {"finding": "a", "id": "SSH-ROOT"}),
                         rule_id("x", {"finding": "totally different", "id": "SSH-ROOT"}))


class CliReports(unittest.TestCase):
    def test_flags_registered(self):
        import main
        a = main.build_parser().parse_args(["--module", "ssl_auditor", "--report-format", "sarif"])
        self.assertEqual(a.report_format, "sarif")


class InterfaceCheck(unittest.TestCase):
    def test_loopback_found_without_ip_binary(self):
        from utils import network_utils as nu
        with mock.patch("subprocess.run", side_effect=FileNotFoundError):
            self.assertTrue(nu.interface_exists("lo"))
            self.assertFalse(nu.interface_exists("definitely-not-nic"))
            self.assertFalse(nu.interface_exists("-V"))

    def test_unverifiable_platform_accepts_valid_name(self):
        from utils import network_utils as nu
        with mock.patch("socket.if_nameindex", side_effect=AttributeError), \
             mock.patch("subprocess.run", side_effect=FileNotFoundError):
            self.assertTrue(nu.interface_exists("en0"))
            self.assertFalse(nu.interface_exists("--help"))


class MissingScapyFails(unittest.TestCase):
    def test_cli_entrypoints_raise_so_cron_sees_failure(self):
        import importlib.util
        if importlib.util.find_spec("scapy") is not None:
            self.skipTest("scapy installed")
        from modules import host_discovery, network_scanner, intrusion_detector
        a = mock.Mock(ip_range="127.0.0.1/32", interface="lo", duration=1,
                      port_scan_threshold=0, syn_flood_threshold=0)
        for mod in (host_discovery, network_scanner, intrusion_detector):
            with self.assertRaises(RuntimeError):
                mod.cli_run(a)


class BannerFallback(unittest.TestCase):
    def test_plain_banner_does_not_crash_without_rich(self):
        from utils import rich_ui
        with mock.patch.object(rich_ui, "RICH_AVAILABLE", False):
            rich_ui.print_banner()


try:
    import flask  # noqa: F401
    HAVE_FLASK = True
except ImportError:
    HAVE_FLASK = False


@unittest.skipUnless(HAVE_FLASK, "flask not installed")
class DashboardFindings(unittest.TestCase):
    def test_pages_render(self):
        from dashboard import app as dash
        c = dash.app.test_client()
        with mock.patch.dict(os.environ, {"TOOLKIT_DASHBOARD_TOKEN": ""}):
            self.assertEqual(c.get("/findings").status_code, 200)
            r = c.get("/api/findings")
            self.assertEqual(r.status_code, 200)
            self.assertIn("open", r.get_json())


if __name__ == "__main__":
    unittest.main()
