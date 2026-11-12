"""Tests for v3.9: SARIF export, suppression register, signed FIM baseline, dashboard auth."""
import json, os, sys, tempfile, unittest
from datetime import date
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import sarif, suppressions
from utils.risk import compute_risk_score

RESULTS = [{
    "scan_type": "ssl_auditor", "target": "example.com",
    "extra": {"findings": [
        {"severity": "High", "finding": "TLS 1.0 enabled", "remediation": "Disable it"},
        {"severity": "Low", "finding": "Missing HSTS preload"},
    ]},
}]


class Sarif(unittest.TestCase):
    def test_structure_and_levels(self):
        doc = sarif.build_sarif({}, RESULTS)
        self.assertEqual(doc["version"], "2.1.0")
        res = doc["runs"][0]["results"]
        self.assertEqual([r["level"] for r in res], ["error", "note"])
        self.assertEqual(len(doc["runs"][0]["tool"]["driver"]["rules"]), 2)

    def test_rule_ids_stable(self):
        f = RESULTS[0]["extra"]["findings"][0]
        self.assertEqual(sarif.rule_id("ssl_auditor", f), sarif.rule_id("ssl_auditor", dict(f)))

    def test_malformed_input_never_raises(self):
        sarif.build_sarif(None, [None, {"extra": None}, {"extra": {"findings": [None, 3]}}])

    def test_suppressed_marked(self):
        rid = sarif.rule_id("ssl_auditor", RESULTS[0]["extra"]["findings"][0])
        doc = sarif.build_sarif({}, RESULTS, {rid})
        self.assertIn("suppressions", doc["runs"][0]["results"][0])
        self.assertNotIn("suppressions", doc["runs"][0]["results"][1])

    def test_write_owner_only(self):
        with tempfile.TemporaryDirectory() as d:
            p = sarif.write_sarif({}, RESULTS, d)
            json.load(open(p))
            self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)


class Suppressions(unittest.TestCase):
    ENTRY = {"match": "tls 1.0", "reason": "legacy", "expires": "2030-01-01"}

    def test_active_and_expired(self):
        f = RESULTS[0]["extra"]["findings"][0]
        self.assertTrue(suppressions.is_suppressed(f, "ssl_auditor", "x", [self.ENTRY], date(2026, 1, 1)))
        self.assertFalse(suppressions.is_suppressed(f, "ssl_auditor", "x", [self.ENTRY], date(2031, 1, 1)))

    def test_missing_or_bad_expiry_ignored(self):
        f = RESULTS[0]["extra"]["findings"][0]
        for bad in ({"match": "tls"}, {"match": "tls", "expires": "someday"}):
            self.assertFalse(suppressions.is_suppressed(f, "ssl_auditor", "x", [bad]))

    def test_target_scoping(self):
        f = RESULTS[0]["extra"]["findings"][0]
        e = dict(self.ENTRY, target="other.com")
        self.assertFalse(suppressions.is_suppressed(f, "ssl_auditor", "example.com", [e], date(2026, 1, 1)))

    def test_risk_reduced_and_counted(self):
        base = compute_risk_score(RESULTS)
        sup = compute_risk_score(RESULTS, suppressions=[self.ENTRY])
        self.assertEqual(sup["suppressed"], 1)
        self.assertLess(sup["score"], base["score"])
        self.assertNotIn("suppressed", base)

    def test_load_missing_file(self):
        self.assertEqual(suppressions.load("/nonexistent/x.json"), [])


class SignedBaseline(unittest.TestCase):
    def test_tamper_detected(self):
        from modules import file_integrity_monitor as fim
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "b.json")
            with mock.patch.object(fim, "BASELINE_PATH", path), \
                 mock.patch.dict(os.environ, {"TOOLKIT_FIM_HMAC_KEY": "k"}):
                fim.save_baseline([d], {"/a": {"sha256": "1"}})
                self.assertFalse(fim.load_baseline()["_tampered"])
                data = json.load(open(path)); data["files"]["/a"]["sha256"] = "2"
                json.dump(data, open(path, "w"))
                self.assertTrue(fim.load_baseline()["_tampered"])

    def test_no_key_no_flag(self):
        from modules import file_integrity_monitor as fim
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "b.json")
            env = {k: v for k, v in os.environ.items() if k != "TOOLKIT_FIM_HMAC_KEY"}
            with mock.patch.object(fim, "BASELINE_PATH", path), mock.patch.dict(os.environ, env, clear=True):
                fim.save_baseline([d], {})
                self.assertNotIn("_tampered", fim.load_baseline())


try:
    import flask  # noqa: F401
    HAVE_FLASK = True
except ImportError:
    HAVE_FLASK = False


@unittest.skipUnless(HAVE_FLASK, "flask not installed")
class DashboardAuth(unittest.TestCase):
    def setUp(self):
        from dashboard import app as dash
        self.dash = dash
        self.client = dash.app.test_client()

    def test_open_when_no_token(self):
        with mock.patch.dict(os.environ, {"TOOLKIT_DASHBOARD_TOKEN": ""}):
            self.assertEqual(self.client.get("/").status_code, 200)

    def test_requires_token(self):
        with mock.patch.dict(os.environ, {"TOOLKIT_DASHBOARD_TOKEN": "s3cret"}):
            self.assertEqual(self.client.get("/").status_code, 401)
            ok = self.client.get("/", headers={"Authorization": "Bearer s3cret"})
            self.assertEqual(ok.status_code, 200)
            bad = self.client.get("/", headers={"Authorization": "Bearer nope"})
            self.assertEqual(bad.status_code, 401)

    def test_query_token_becomes_cookie(self):
        with mock.patch.dict(os.environ, {"TOOLKIT_DASHBOARD_TOKEN": "s3cret"}):
            r = self.client.get("/?token=s3cret")
            self.assertEqual(r.status_code, 302)
            self.assertNotIn("token=", r.headers["Location"])
            self.assertEqual(self.client.get("/").status_code, 200)


if __name__ == "__main__":
    unittest.main()
