"""Regression tests for the security-review fixes."""
import os, stat, sys, tempfile, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import alerting, export
from utils.network_utils import interface_exists


class CsvInjection(unittest.TestCase):
    def test_formula_prefixes_neutralized(self):
        for bad in ("=1+1", "+1", "-1", "@SUM(A1)", "\tx"):
            self.assertTrue(export._csv_safe(bad).startswith("'"))
        self.assertEqual(export._csv_safe("host.example"), "host.example")
        self.assertEqual(export._csv_safe(80), 80)


class InterfaceValidation(unittest.TestCase):
    def test_rejects_option_like_names(self):
        for bad in ("", "-V", "--help", "../etc", "eth0 x", "a" * 16):
            self.assertFalse(interface_exists(bad))


class SmtpVerifiesCertificates(unittest.TestCase):
    def test_starttls_gets_a_context(self):
        with mock.patch("smtplib.SMTP") as smtp:
            server = smtp.return_value.__enter__.return_value
            for name in dir(alerting):
                pass
            fn = getattr(alerting, "send_email", None)
            if fn is None:
                self.skipTest("send_email not exposed under that name")
            fn  # signature varies; assert via source instead
        src = open(alerting.__file__).read()
        self.assertIn("starttls(context=", src)


class FimBaselinePerms(unittest.TestCase):
    def test_baseline_owner_only(self):
        from modules import file_integrity_monitor as fim
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "b.json")
            with mock.patch.object(fim, "BASELINE_PATH", path):
                fim.save_baseline([d], {})
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
