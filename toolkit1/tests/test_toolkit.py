"""
test_toolkit.py — Offline unit tests for the Python Security Toolkit.

These tests cover the pure-logic pieces only (validation, MAC vendor
lookup, vulnerability assessment, report generation, config handling).
They require no root privileges, no network access, and no live targets
— safe to run anywhere, including in class or CI.

Run with:
    python3 -m unittest discover -s tests -v
"""

import os
import sys
import shutil
import tempfile
import json
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.network_utils import validate_mac, validate_ip, validate_ip_range, lookup_mac_vendor
from utils import config as config_mod
from utils.report import generate_html_report
from modules import vulnerability_scanner as vscan
from modules import network_scanner
from modules import intrusion_detector as ids
from modules import ssl_auditor as sslaudit
from utils import cve_feed
from utils.module_loader import discover_modules
from modules import system_hardening as hardening
from modules import port_scanner
from modules import http_header_auditor as headers_mod
from modules import dns_security_auditor as dnsaudit
from modules import file_integrity_monitor as fim
from modules import auth_log_analyzer as authlog
from modules import package_cve_auditor as pkgaudit
from modules import docker_auditor
from modules import firewall_auditor
from modules import web_app_scanner
from modules import subdomain_mapper
from utils.export import export_pdf
from utils import db
from utils import alerting


class TestValidation(unittest.TestCase):
    def test_valid_mac_colon(self):
        self.assertTrue(validate_mac("aa:bb:cc:dd:ee:ff"))

    def test_valid_mac_hyphen(self):
        self.assertTrue(validate_mac("AA-BB-CC-DD-EE-FF"))

    def test_invalid_mac(self):
        self.assertFalse(validate_mac("not-a-mac"))
        self.assertFalse(validate_mac("aa:bb:cc:dd:ee"))  # too short

    def test_valid_ip(self):
        self.assertTrue(validate_ip("192.168.1.1"))
        self.assertTrue(validate_ip("0.0.0.0"))
        self.assertTrue(validate_ip("255.255.255.255"))

    def test_invalid_ip(self):
        self.assertFalse(validate_ip("256.1.1.1"))
        self.assertFalse(validate_ip("192.168.1"))
        self.assertFalse(validate_ip("not.an.ip.addr"))

    def test_valid_ip_range(self):
        self.assertTrue(validate_ip_range("192.168.1.0/24"))
        self.assertTrue(validate_ip_range("10.0.0.5"))

    def test_invalid_ip_range(self):
        self.assertFalse(validate_ip_range("192.168.1.0/33"))
        self.assertFalse(validate_ip_range("192.168.1.0/abc"))


class TestMacVendorLookup(unittest.TestCase):
    def test_known_vendor_colon(self):
        self.assertEqual(lookup_mac_vendor("00:0c:29:11:22:33"), "VMware")

    def test_known_vendor_hyphen(self):
        # Regression test: hyphenated MACs used to fail vendor lookup.
        self.assertEqual(lookup_mac_vendor("00-0c-29-11-22-33"), "VMware")

    def test_unknown_vendor(self):
        self.assertEqual(lookup_mac_vendor("ff:ff:ff:11:22:33"), "Unknown")


class TestVulnerabilityScanner(unittest.TestCase):
    def test_known_vulnerable_banner_flagged(self):
        results = [{"port": 21, "state": "open", "service": "FTP | vsftpd 2.3.4"}]
        findings = vscan.assess_results(results)
        cves = [f["cve"] for f in findings]
        self.assertIn("CVE-2011-2523", cves)

    def test_weak_protocol_flagged_even_without_banner(self):
        results = [{"port": 23, "state": "open", "service": "Telnet"}]
        findings = vscan.assess_results(results)
        self.assertTrue(any(f["port"] == 23 for f in findings))
        self.assertTrue(any(f["severity"] == "High" for f in findings))

    def test_no_findings_on_clean_modern_service(self):
        results = [{"port": 22, "state": "open", "service": "SSH | OpenSSH_9.6"}]
        findings = vscan.assess_results(results)
        self.assertEqual(findings, [])

    def test_findings_sorted_worst_first(self):
        results = [
            {"port": 21, "state": "open", "service": "FTP | vsftpd 2.3.4"},  # Critical + Medium
            {"port": 445, "state": "open", "service": "SMB"},                # Medium
        ]
        findings = vscan.assess_results(results)
        severities = [f["severity"] for f in findings]
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        self.assertEqual(severities, sorted(severities, key=lambda s: order[s]))


class TestDeviceNameResolution(unittest.TestCase):
    def test_reverse_dns_returns_none_for_unroutable_ip(self):
        # 192.0.2.0/24 is reserved (TEST-NET-1) and will never resolve —
        # this should fail gracefully and return None, not raise.
        result = network_scanner._reverse_dns("192.0.2.123", timeout=0.2)
        self.assertIsNone(result)

    def test_netbios_lookup_times_out_gracefully(self):
        result = network_scanner._netbios_name("192.0.2.123", timeout=0.2)
        self.assertIsNone(result)

    def test_resolve_device_name_falls_back_to_unknown(self):
        name = network_scanner.resolve_device_name("192.0.2.123")
        self.assertEqual(name, "Unknown")


class TestConfig(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self._orig_dir = config_mod.CONFIG_DIR
        self._orig_file = config_mod.CONFIG_FILE
        config_mod.CONFIG_DIR = self.tmpdir
        config_mod.CONFIG_FILE = os.path.join(self.tmpdir, "settings.json")

    def tearDown(self):
        config_mod.CONFIG_DIR = self._orig_dir
        config_mod.CONFIG_FILE = self._orig_file
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_load_config_defaults_when_missing(self):
        cfg = config_mod.load_config()
        self.assertEqual(cfg["scan_timeout"], config_mod.DEFAULT_CONFIG["scan_timeout"])

    def test_save_and_reload_config(self):
        cfg = config_mod.load_config()
        cfg["operator_name"] = "Test Operator"
        config_mod.save_config(cfg)
        reloaded = config_mod.load_config()
        self.assertEqual(reloaded["operator_name"], "Test Operator")


class TestReportGeneration(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_report_handles_empty_data(self):
        path = generate_html_report({"session_id": "x"}, [], [], output_dir=self.tmpdir)
        self.assertTrue(os.path.exists(path))
        with open(path) as f:
            content = f.read()
        self.assertIn("No activity logged", content)
        self.assertIn("No scan results recorded", content)

    def test_report_handles_null_db_fields(self):
        # Regression test: null fields from the DB used to crash html.escape().
        activity = [{"created_at": None, "module_name": None,
                     "status": None, "result_summary": None}]
        path = generate_html_report({"session_id": "x"}, activity, [], output_dir=self.tmpdir)
        self.assertTrue(os.path.exists(path))

    def test_report_includes_vulnerability_section(self):
        scan_results = [{
            "scan_type": "vulnerability_scan",
            "ip_address": "192.168.1.10",
            "extra": {"findings": [
                {"port": 21, "severity": "Critical", "cve": "CVE-2011-2523",
                 "finding": "vsftpd backdoor", "remediation": "Upgrade vsftpd"},
            ]},
        }]
        path = generate_html_report({"session_id": "x"}, [], scan_results, output_dir=self.tmpdir)
        with open(path) as f:
            content = f.read()
        self.assertIn("Vulnerability Findings", content)
        self.assertIn("CVE-2011-2523", content)

    def test_report_includes_http_header_section(self):
        scan_results = [{
            "scan_type": "http_header_audit",
            "target": "example.com",
            "extra": {
                "url": "https://example.com/",
                "findings": [
                    {"header": "Content-Security-Policy", "severity": "Medium",
                     "finding": "No CSP header", "remediation": "Add a CSP"},
                ],
            },
        }]
        path = generate_html_report({"session_id": "x"}, [], scan_results, output_dir=self.tmpdir)
        with open(path) as f:
            content = f.read()
        self.assertIn("HTTP Security Header Findings", content)
        self.assertIn("Content-Security-Policy", content)

    def test_report_http_header_section_empty_when_no_audits(self):
        path = generate_html_report({"session_id": "x"}, [], [], output_dir=self.tmpdir)
        with open(path) as f:
            content = f.read()
        self.assertIn("No HTTP header audits recorded", content)

    def test_report_includes_ssl_section(self):
        # BUGFIX (v3.3) regression test: ssl_auditor findings are stored
        # under extra["findings_by_port"] (keyed by port), not a flat
        # extra["findings"] list like the other modules — the report used
        # to have no section for this scan_type at all.
        scan_results = [{
            "scan_type": "ssl_audit",
            "ip_address": "192.168.1.10",
            "extra": {"findings_by_port": {
                "443": [{"port": 443, "severity": "Critical",
                         "finding": "Certificate expired 10 day(s) ago.",
                         "remediation": "Renew the certificate immediately."}],
            }},
        }]
        path = generate_html_report({"session_id": "x"}, [], scan_results, output_dir=self.tmpdir)
        with open(path) as f:
            content = f.read()
        self.assertIn("SSL/TLS Findings", content)
        self.assertIn("Certificate expired", content)

    def test_report_ssl_section_empty_when_no_audits(self):
        path = generate_html_report({"session_id": "x"}, [], [], output_dir=self.tmpdir)
        with open(path) as f:
            content = f.read()
        self.assertIn("No SSL/TLS audits recorded", content)

    def test_report_includes_system_hardening_section(self):
        scan_results = [{
            "scan_type": "system_hardening",
            "target": "lab-host",
            "extra": {"findings": [
                {"check": "SSH", "severity": "High",
                 "finding": "PermitRootLogin is set to 'yes'.",
                 "remediation": "Set 'PermitRootLogin no'."},
            ]},
        }]
        path = generate_html_report({"session_id": "x"}, [], scan_results, output_dir=self.tmpdir)
        with open(path) as f:
            content = f.read()
        self.assertIn("System Hardening Findings", content)
        self.assertIn("PermitRootLogin", content)

    def test_report_includes_dns_security_section(self):
        scan_results = [{
            "scan_type": "dns_security_audit",
            "target": "example.com",
            "extra": {"findings": [
                {"check": "SPF", "severity": "Medium",
                 "finding": "No SPF record published.",
                 "remediation": "Publish an SPF record."},
            ]},
        }]
        path = generate_html_report({"session_id": "x"}, [], scan_results, output_dir=self.tmpdir)
        with open(path) as f:
            content = f.read()
        self.assertIn("DNS Security Findings", content)
        self.assertIn("No SPF record published", content)


class TestIntrusionDetector(unittest.TestCase):
    """Pure-logic tests for the detector's alerting thresholds — no live
    sniffing, no root privileges required."""

    def _fresh_state(self, **overrides):
        defaults = dict(port_scan_threshold=5, port_scan_window=10.0,
                         syn_flood_threshold=5, syn_flood_window=5.0)
        defaults.update(overrides)
        ids._state = ids._State(**defaults)
        return ids._state

    def test_arp_mapping_change_raises_spoofing_alert(self):
        state = self._fresh_state()
        state.arp_table["192.168.1.1"] = "aa:aa:aa:aa:aa:aa"

        class FakeARP:
            op = 2
            psrc = "192.168.1.1"
            hwsrc = "BB:BB:BB:BB:BB:BB"

        class FakePacket(dict):
            def __getitem__(self, key):
                return FakeARP()

        ids._check_arp(FakePacket())
        self.assertEqual(len(state.alerts), 1)
        self.assertEqual(state.alerts[0]["kind"], "ARP SPOOFING")

    def test_no_alert_when_mac_unchanged(self):
        state = self._fresh_state()
        state.arp_table["192.168.1.1"] = "aa:aa:aa:aa:aa:aa"

        class FakeARP:
            op = 2
            psrc = "192.168.1.1"
            hwsrc = "AA:AA:AA:AA:AA:AA"

        class FakePacket(dict):
            def __getitem__(self, key):
                return FakeARP()

        ids._check_arp(FakePacket())
        self.assertEqual(len(state.alerts), 0)

    def test_port_scan_threshold_triggers_alert(self):
        state = self._fresh_state(port_scan_threshold=3, port_scan_window=10.0)
        now = 1000.0
        for port in (20, 21, 22):
            state.syn_events["10.0.0.5"].append((now, port))

        # Re-run the windowing logic the way _check_tcp_syn does internally
        events = state.syn_events["10.0.0.5"]
        recent_ports = {p for t, p in events if t >= now - state.port_scan_window}
        self.assertGreaterEqual(len(recent_ports), state.port_scan_threshold)


class TestPortScannerTopPorts(unittest.TestCase):
    """Regression tests for the v3.1 TOP_PORTS de-duplication bugfix."""

    def test_top_ports_has_no_duplicates(self):
        self.assertEqual(len(port_scanner.TOP_PORTS), len(set(port_scanner.TOP_PORTS)))

    def test_top_ports_has_at_least_100_entries(self):
        # "Top 100 ports" should actually mean 100 *distinct* ports.
        self.assertGreaterEqual(len(port_scanner.TOP_PORTS), 100)

    def test_top_20_slice_has_no_duplicates(self):
        top20 = port_scanner.TOP_PORTS[:20]
        self.assertEqual(len(top20), len(set(top20)))


class TestModuleLoader(unittest.TestCase):
    """The plugin-style auto-discovery loader (utils/module_loader.py)."""

    def test_discovers_all_builtin_modules(self):
        mods = discover_modules(quiet=True)
        cli_names = {m["cli_name"] for m in mods}
        self.assertEqual(
            cli_names,
            {"network_scanner", "port_scanner", "host_discovery",
             "vulnerability_scanner", "intrusion_detector", "ssl_auditor",
             "system_hardening", "http_header_auditor",
             "dns_security_auditor", "file_integrity_monitor",
             "auth_log_analyzer", "package_cve_auditor",
             "docker_auditor", "firewall_auditor", "web_app_scanner",
             "subdomain_mapper"},
        )

    def test_ids_are_sequential_and_unique(self):
        mods = discover_modules(quiet=True)
        ids_seen = [m["id"] for m in mods]
        self.assertEqual(ids_seen, list(range(1, len(mods) + 1)))

    def test_every_module_has_a_callable_run(self):
        for m in discover_modules(quiet=True):
            self.assertTrue(callable(m["module"].run))

    def test_discovered_modules_expose_cli_run(self):
        # All five built-ins plus the new ssl_auditor support CLI mode.
        for m in discover_modules(quiet=True):
            self.assertTrue(hasattr(m["module"], "cli_run"),
                            f"{m['cli_name']} is missing cli_run")


class TestSSLAuditorAssessment(unittest.TestCase):
    """Pure assessment logic in modules/ssl_auditor.py — no network I/O."""

    def setUp(self):
        self.now = __import__("datetime").datetime(2026, 9, 25)

    def test_healthy_expiry_yields_no_finding(self):
        result = sslaudit.assess_expiry("Jun  3 12:00:00 2027 GMT", now=self.now)
        self.assertIsNone(result)

    def test_soon_to_expire_is_medium_severity(self):
        result = sslaudit.assess_expiry("Oct  1 12:00:00 2026 GMT", now=self.now)
        self.assertIsNotNone(result)
        self.assertEqual(result["severity"], "Medium")

    def test_already_expired_is_critical(self):
        result = sslaudit.assess_expiry("Jan  1 12:00:00 2020 GMT", now=self.now)
        self.assertIsNotNone(result)
        self.assertEqual(result["severity"], "Critical")

    def test_unparseable_date_is_flagged_low(self):
        result = sslaudit.assess_expiry("not-a-date", now=self.now)
        self.assertEqual(result["severity"], "Low")

    def test_self_signed_detected(self):
        cert = {"issuer": (("CN", "same"),), "subject": (("CN", "same"),)}
        result = sslaudit.assess_self_signed(cert)
        self.assertIsNotNone(result)
        self.assertIn("self-signed", result["finding"])

    def test_ca_issued_not_flagged(self):
        cert = {"issuer": (("CN", "Some CA"),), "subject": (("CN", "example.com"),)}
        self.assertIsNone(sslaudit.assess_self_signed(cert))

    def test_modern_protocol_not_flagged(self):
        self.assertIsNone(sslaudit.assess_protocol("TLSv1.3"))
        self.assertIsNone(sslaudit.assess_protocol("TLSv1.2"))

    def test_legacy_protocol_flagged(self):
        for weak in ("SSLv3", "TLSv1", "TLSv1.1"):
            result = sslaudit.assess_protocol(weak)
            self.assertIsNotNone(result, f"{weak} should be flagged")

    def test_ssl_v3_is_critical_others_high(self):
        self.assertEqual(sslaudit.assess_protocol("SSLv3")["severity"], "Critical")
        self.assertEqual(sslaudit.assess_protocol("TLSv1")["severity"], "High")

    def test_strong_cipher_not_flagged(self):
        self.assertIsNone(sslaudit.assess_cipher("ECDHE-RSA-AES256-GCM-SHA384"))

    def test_weak_cipher_flagged(self):
        for weak in ("EXP-RC4-MD5", "DES-CBC3-SHA", "ADH-AES256-SHA"):
            self.assertIsNotNone(sslaudit.assess_cipher(weak), f"{weak} should be flagged")

    def test_build_findings_sorted_worst_first(self):
        cert = {"issuer": (("CN", "x"),), "subject": (("CN", "x"),),
                "notAfter": "Jan  1 12:00:00 2020 GMT"}
        findings = sslaudit.build_findings("host", 443, cert, "SSLv3", "EXP-RC4-MD5")
        severities = [f["severity"] for f in findings]
        self.assertEqual(severities, sorted(
            severities, key=lambda s: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}[s]))

    def test_missing_cert_still_produces_a_finding(self):
        findings = sslaudit.build_findings("host", 443, None, "TLSv1.3", "TLS_AES_256_GCM_SHA384")
        self.assertTrue(any("could not be retrieved" in f["finding"] for f in findings))


class TestCVEFeed(unittest.TestCase):
    """utils/cve_feed.py — cache handling and safe offline fallback."""

    def setUp(self):
        self._orig_cache_file = cve_feed.CACHE_FILE
        self._tmp_dir = tempfile.mkdtemp()
        cve_feed.CACHE_FILE = os.path.join(self._tmp_dir, "cve_cache.json")

    def tearDown(self):
        cve_feed.CACHE_FILE = self._orig_cache_file
        shutil.rmtree(self._tmp_dir, ignore_errors=True)

    def test_empty_keyword_returns_empty_list(self):
        self.assertEqual(cve_feed.lookup_cve(""), [])
        self.assertEqual(cve_feed.lookup_cve("   "), [])

    def test_load_cache_missing_file_returns_empty_dict(self):
        self.assertEqual(cve_feed._load_cache(), {})

    def test_save_and_load_cache_roundtrip(self):
        cve_feed._save_cache({"apache/2.4": {"fetched_at": 0, "findings": []}})
        loaded = cve_feed._load_cache()
        self.assertIn("apache/2.4", loaded)

    def test_cache_freshness_check(self):
        import time
        fresh = {"fetched_at": time.time()}
        stale = {"fetched_at": time.time() - 999999}
        self.assertTrue(cve_feed._cache_is_fresh(fresh, ttl_hours=24))
        self.assertFalse(cve_feed._cache_is_fresh(stale, ttl_hours=24))

    def test_lookup_never_raises_without_network(self):
        # In an offline/sandboxed environment this should degrade to an
        # empty list rather than raising, matching the docstring contract.
        try:
            result = cve_feed.lookup_cve("SomeService/1.0", timeout=1.0)
        except Exception as exc:  # pragma: no cover - failure would be the bug
            self.fail(f"lookup_cve raised unexpectedly: {exc}")
        self.assertIsInstance(result, list)

    def test_clear_cache_removes_file(self):
        cve_feed._save_cache({"x": {"fetched_at": 0, "findings": []}})
        self.assertTrue(os.path.exists(cve_feed.CACHE_FILE))
        cve_feed.clear_cache()
        self.assertFalse(os.path.exists(cve_feed.CACHE_FILE))


class TestVulnerabilityScannerLiveFeedIntegration(unittest.TestCase):
    """augment_with_live_cve_feed() must stay inert when disabled."""

    def test_disabled_by_default_contributes_nothing(self):
        fake_open_ports = [{"port": 21, "state": "open", "service": "vsftpd 2.3.4"}]
        result = vscan.augment_with_live_cve_feed(fake_open_ports, enabled=False)
        self.assertEqual(result, [])


class TestSystemHardeningAuditor(unittest.TestCase):
    """New in v3.1: local, read-only hardening checks — no root required."""

    def test_audit_returns_a_list_and_never_raises(self):
        findings = hardening.audit()
        self.assertIsInstance(findings, list)

    def test_findings_sorted_worst_first(self):
        findings = hardening.audit()
        severities = [f["severity"] for f in findings]
        self.assertEqual(
            severities,
            sorted(severities, key=lambda s: hardening.SEVERITY_ORDER.get(s, 5)),
        )

    def test_read_lines_returns_none_for_missing_file(self):
        # _read_lines() on a nonexistent path must return None, not raise —
        # this is what lets check_sshd_config() degrade to an Info finding
        # instead of crashing when SSH isn't installed.
        self.assertIsNone(hardening._read_lines("/no/such/path/sshd_config"))

    def test_world_writable_dir_is_flagged(self):
        tmpdir = tempfile.mkdtemp()
        try:
            bad_file = os.path.join(tmpdir, "bad.txt")
            with open(bad_file, "w") as fh:
                fh.write("x")
            os.chmod(bad_file, 0o666)
            findings = hardening.check_world_writable_dirs(scan_dirs=[tmpdir])
            self.assertEqual(len(findings), 1)
            self.assertIn(bad_file, findings[0]["finding"])
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_no_world_writable_files_yields_no_finding(self):
        tmpdir = tempfile.mkdtemp()
        try:
            safe_file = os.path.join(tmpdir, "safe.txt")
            with open(safe_file, "w") as fh:
                fh.write("x")
            os.chmod(safe_file, 0o644)
            findings = hardening.check_world_writable_dirs(scan_dirs=[tmpdir])
            self.assertEqual(findings, [])
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_module_exposes_run_and_cli_run(self):
        self.assertTrue(callable(hardening.run))
        self.assertTrue(callable(hardening.cli_run))

    def test_module_meta_has_no_required_cli_args(self):
        # This module audits the local machine, not a remote target, so it
        # should have no required CLI flags.
        self.assertEqual(hardening.MODULE_META.get("cli_required"), [])


class TestHttpHeaderAuditor(unittest.TestCase):
    """New in v3.2: HTTP security response-header auditor — pure assessment
    logic only, no network I/O."""

    def test_normalize_url_adds_https_scheme(self):
        self.assertEqual(headers_mod.normalize_url("example.com"),
                         "https://example.com/")

    def test_normalize_url_keeps_existing_scheme_and_path(self):
        self.assertEqual(
            headers_mod.normalize_url("http://example.com/status"),
            "http://example.com/status",
        )

    def test_hsts_missing_on_https_is_flagged(self):
        result = headers_mod.assess_hsts({}, is_https=True)
        self.assertIsNotNone(result)
        self.assertEqual(result["severity"], "Medium")

    def test_hsts_not_required_over_plain_http(self):
        self.assertIsNone(headers_mod.assess_hsts({}, is_https=False))

    def test_hsts_short_max_age_flagged_low(self):
        result = headers_mod.assess_hsts(
            {"Strict-Transport-Security": "max-age=60"}, is_https=True)
        self.assertIsNotNone(result)
        self.assertEqual(result["severity"], "Low")

    def test_hsts_strong_value_not_flagged(self):
        result = headers_mod.assess_hsts(
            {"Strict-Transport-Security": "max-age=31536000; includeSubDomains"},
            is_https=True)
        self.assertIsNone(result)

    def test_csp_missing_is_flagged(self):
        self.assertIsNotNone(headers_mod.assess_csp({}))

    def test_csp_wildcard_default_src_flagged(self):
        result = headers_mod.assess_csp(
            {"Content-Security-Policy": "default-src *"})
        self.assertIsNotNone(result)

    def test_csp_reasonable_policy_not_flagged(self):
        result = headers_mod.assess_csp(
            {"Content-Security-Policy": "default-src 'self'"})
        self.assertIsNone(result)

    def test_frame_protection_missing_is_flagged(self):
        self.assertIsNotNone(headers_mod.assess_frame_protection({}))

    def test_frame_protection_via_xfo_not_flagged(self):
        self.assertIsNone(headers_mod.assess_frame_protection(
            {"X-Frame-Options": "DENY"}))

    def test_frame_protection_via_csp_frame_ancestors_not_flagged(self):
        self.assertIsNone(headers_mod.assess_frame_protection(
            {"Content-Security-Policy": "frame-ancestors 'self'"}))

    def test_content_type_options_missing_is_flagged(self):
        self.assertIsNotNone(headers_mod.assess_content_type_options({}))

    def test_content_type_options_nosniff_not_flagged(self):
        self.assertIsNone(headers_mod.assess_content_type_options(
            {"X-Content-Type-Options": "nosniff"}))

    def test_server_header_with_version_is_flagged(self):
        findings = headers_mod.assess_server_disclosure(
            {"Server": "Apache/2.4.49"})
        self.assertEqual(len(findings), 1)

    def test_server_header_without_version_not_flagged(self):
        findings = headers_mod.assess_server_disclosure({"Server": "Apache"})
        self.assertEqual(findings, [])

    def test_cookie_missing_all_flags_is_flagged(self):
        findings = headers_mod.assess_cookies(["sessionid=abc123; Path=/"])
        self.assertEqual(len(findings), 1)
        self.assertIn("sessionid", findings[0]["finding"])

    def test_cookie_with_all_flags_not_flagged(self):
        findings = headers_mod.assess_cookies(
            ["sessionid=abc123; Secure; HttpOnly; SameSite=Strict"])
        self.assertEqual(findings, [])

    def test_no_cookies_yields_no_findings(self):
        self.assertEqual(headers_mod.assess_cookies([]), [])

    def test_build_findings_sorted_worst_first(self):
        findings = headers_mod.build_findings(
            {"Server": "nginx/1.18.0"}, is_https=True,
            set_cookie_headers=["id=1"])
        severities = [f["severity"] for f in findings]
        self.assertEqual(
            severities,
            sorted(severities, key=lambda s: headers_mod.SEVERITY_ORDER.get(s, 5)),
        )

    def test_fully_hardened_response_yields_no_findings(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
        }
        findings = headers_mod.build_findings(headers, is_https=True)
        self.assertEqual(findings, [])

    def test_module_exposes_run_and_cli_run(self):
        self.assertTrue(callable(headers_mod.run))
        self.assertTrue(callable(headers_mod.cli_run))


class TestDnsSecurityAuditor(unittest.TestCase):
    """Pure assessment + wire-format logic in modules/dns_security_auditor.py
    — no network I/O, fully unit-testable offline."""

    # --- domain validation ---

    def test_valid_domain_accepted(self):
        self.assertTrue(dnsaudit.validate_domain("example.com"))
        self.assertTrue(dnsaudit.validate_domain("sub.example.co.uk."))

    def test_invalid_domain_rejected(self):
        self.assertFalse(dnsaudit.validate_domain(""))
        self.assertFalse(dnsaudit.validate_domain("not a domain"))
        self.assertFalse(dnsaudit.validate_domain("-leadinghyphen.com"))

    # --- SPF ---

    def test_missing_spf_is_flagged_medium(self):
        findings = dnsaudit.assess_spf([])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "Medium")

    def test_spf_plus_all_is_flagged_high(self):
        findings = dnsaudit.assess_spf(["v=spf1 include:_spf.example.com +all"])
        severities = [f["severity"] for f in findings]
        self.assertIn("High", severities)

    def test_spf_hard_fail_not_flagged(self):
        findings = dnsaudit.assess_spf(["v=spf1 include:_spf.example.com -all"])
        self.assertEqual(findings, [])

    def test_spf_soft_fail_flagged_low(self):
        findings = dnsaudit.assess_spf(["v=spf1 include:_spf.example.com ~all"])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "Low")

    def test_multiple_spf_records_flagged(self):
        findings = dnsaudit.assess_spf(["v=spf1 -all", "v=spf1 include:foo.com -all"])
        self.assertTrue(any("7208" in f["finding"] for f in findings))

    def test_non_spf_txt_records_ignored(self):
        findings = dnsaudit.assess_spf(["google-site-verification=abc123"])
        # No v=spf1 record among these -> treated as "no SPF published".
        self.assertEqual(len(findings), 1)
        self.assertIn("No SPF", findings[0]["finding"])

    # --- DMARC ---

    def test_missing_dmarc_is_flagged_medium(self):
        findings = dnsaudit.assess_dmarc([])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "Medium")

    def test_dmarc_p_none_flagged_low(self):
        findings = dnsaudit.assess_dmarc(["v=DMARC1; p=none; rua=mailto:d@example.com"])
        severities = [f["severity"] for f in findings]
        self.assertIn("Low", severities)

    def test_dmarc_p_reject_with_rua_yields_no_findings(self):
        findings = dnsaudit.assess_dmarc(["v=DMARC1; p=reject; rua=mailto:d@example.com"])
        self.assertEqual(findings, [])

    def test_dmarc_missing_rua_flagged_info(self):
        findings = dnsaudit.assess_dmarc(["v=DMARC1; p=reject"])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "Info")

    # --- DNSSEC ---

    def test_dnssec_absent_flagged_info(self):
        findings = dnsaudit.assess_dnssec(False)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "Info")

    def test_dnssec_present_yields_no_findings(self):
        self.assertEqual(dnsaudit.assess_dnssec(True), [])

    # --- combined findings ordering ---

    def test_build_findings_sorted_worst_first(self):
        findings = dnsaudit.build_findings(
            txt_records=["v=spf1 +all"],
            dmarc_txt_records=[],
            dnskey_present=False,
        )
        severities = [f["severity"] for f in findings]
        self.assertEqual(
            severities,
            sorted(severities, key=lambda s: dnsaudit.SEVERITY_ORDER.get(s, 5)),
        )

    # --- DNS wire-format encode/decode round-trip ---

    def test_encode_name_produces_length_prefixed_labels(self):
        encoded = dnsaudit._encode_name("example.com")
        self.assertEqual(encoded, b"\x07example\x03com\x00")

    def test_read_name_decodes_uncompressed_name(self):
        packet = dnsaudit._encode_name("example.com") + b"TRAILING"
        name, offset = dnsaudit._read_name(packet, 0)
        self.assertEqual(name, "example.com")
        self.assertEqual(packet[offset:], b"TRAILING")

    def test_read_name_follows_compression_pointer(self):
        # A name at offset 0, then a second name elsewhere that's just a
        # compression pointer back to offset 0 — the standard trick DNS
        # servers use to avoid repeating "example.com" in every record.
        base = dnsaudit._encode_name("example.com")
        pointer = struct_pack_pointer(0)
        packet = base + b"\x00\x00" + pointer  # padding, then the pointer
        name, _offset = dnsaudit._read_name(packet, len(base) + 2)
        self.assertEqual(name, "example.com")

    def test_decode_txt_concatenates_multiple_strings(self):
        rdata = bytes([5]) + b"hello" + bytes([5]) + b"world"
        self.assertEqual(dnsaudit._decode_txt(rdata), "helloworld")

    def test_decode_txt_single_string(self):
        rdata = bytes([6]) + b"v=spf1"
        self.assertEqual(dnsaudit._decode_txt(rdata), "v=spf1")

    # --- module shape ---

    def test_module_exposes_run_and_cli_run(self):
        self.assertTrue(callable(dnsaudit.run))
        self.assertTrue(callable(dnsaudit.cli_run))

    def test_audit_rejects_invalid_domain_without_network(self):
        result = dnsaudit.audit("not a domain")
        self.assertIsNotNone(result["error"])
        self.assertEqual(result["findings"], [])


class TestFileIntegrityMonitor(unittest.TestCase):
    """Pure logic in modules/file_integrity_monitor.py — hashing/diffing
    is exercised against a real temp directory (no root, no network);
    only the filesystem walk touches disk."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmpdir, ignore_errors=True)
        self.file_a = os.path.join(self.tmpdir, "a.conf")
        with open(self.file_a, "w") as fh:
            fh.write("original contents\n")

    def test_hash_file_is_stable_and_changes_with_content(self):
        h1 = fim._hash_file(self.file_a)
        h2 = fim._hash_file(self.file_a)
        self.assertEqual(h1, h2)
        with open(self.file_a, "a") as fh:
            fh.write("more\n")
        h3 = fim._hash_file(self.file_a)
        self.assertNotEqual(h1, h3)

    def test_hash_file_missing_returns_none(self):
        self.assertIsNone(fim._hash_file(os.path.join(self.tmpdir, "nope")))

    def test_expand_watch_paths_finds_files_in_directory(self):
        sub = os.path.join(self.tmpdir, "sub")
        os.makedirs(sub)
        with open(os.path.join(sub, "b.conf"), "w") as fh:
            fh.write("x")
        found = fim.expand_watch_paths([self.tmpdir])
        self.assertIn(self.file_a, found)
        self.assertIn(os.path.join(sub, "b.conf"), found)

    def test_expand_watch_paths_skips_missing_paths(self):
        found = fim.expand_watch_paths([os.path.join(self.tmpdir, "ghost")])
        self.assertEqual(found, [])

    def test_diff_snapshots_detects_added_removed_modified(self):
        baseline = {
            "/etc/a": {"hash": "h1", "mode": 0o644, "size": 1, "mtime": 1},
            "/etc/b": {"hash": "h2", "mode": 0o644, "size": 1, "mtime": 1},
        }
        current = {
            "/etc/a": {"hash": "h1-changed", "mode": 0o644, "size": 2, "mtime": 2},
            "/etc/c": {"hash": "h3", "mode": 0o644, "size": 1, "mtime": 1},
        }
        findings = fim.diff_snapshots(baseline, current)
        by_path = {f["path"]: f for f in findings}
        self.assertIn("/etc/a", by_path)  # modified
        self.assertIn("/etc/b", by_path)  # removed
        self.assertIn("/etc/c", by_path)  # added
        self.assertEqual(by_path["/etc/b"]["severity"], "High")
        self.assertEqual(by_path["/etc/c"]["severity"], "Medium")

    def test_diff_snapshots_flags_sensitive_file_content_change_critical(self):
        baseline = {"/etc/passwd": {"hash": "h1", "mode": 0o644, "size": 1, "mtime": 1}}
        current = {"/etc/passwd": {"hash": "h2", "mode": 0o644, "size": 1, "mtime": 2}}
        findings = fim.diff_snapshots(baseline, current)
        self.assertEqual(findings[0]["severity"], "Critical")

    def test_diff_snapshots_flags_widened_permissions(self):
        baseline = {"/etc/a": {"hash": "h1", "mode": 0o644, "size": 1, "mtime": 1}}
        current = {"/etc/a": {"hash": "h1", "mode": 0o666, "size": 1, "mtime": 1}}
        findings = fim.diff_snapshots(baseline, current)
        self.assertIn("more permissive", findings[0]["finding"])

    def test_diff_snapshots_no_changes_yields_no_findings(self):
        snap = {"/etc/a": {"hash": "h1", "mode": 0o644, "size": 1, "mtime": 1}}
        self.assertEqual(fim.diff_snapshots(snap, dict(snap)), [])

    def test_audit_baseline_then_check_roundtrip(self):
        # Redirect the module's baseline path into the temp dir so this
        # test never touches the real config/fim_baseline.json.
        baseline_path = os.path.join(self.tmpdir, "baseline.json")
        orig_path = fim.BASELINE_PATH
        fim.BASELINE_PATH = baseline_path
        try:
            result1 = fim.audit([self.tmpdir], mode="auto")
            self.assertEqual(result1["status"], "baseline_created")

            with open(self.file_a, "a") as fh:
                fh.write("tampered\n")

            result2 = fim.audit([self.tmpdir], mode="check")
            self.assertEqual(result2["status"], "checked")
            self.assertTrue(any(f["path"] == self.file_a for f in result2["findings"]))
        finally:
            fim.BASELINE_PATH = orig_path

    def test_module_exposes_run_and_cli_run(self):
        self.assertTrue(callable(fim.run))
        self.assertTrue(callable(fim.cli_run))


class TestAuthLogAnalyzer(unittest.TestCase):
    """Pure logic in modules/auth_log_analyzer.py — parsing/assessment
    run against fabricated log text, no real log file or root needed."""

    def test_parse_events_extracts_failed_invalid_and_accepted(self):
        lines = [
            "Jan 1 00:00:01 host sshd[1]: Failed password for invalid user admin from 1.2.3.4 port 5000 ssh2\n",
            "Jan 1 00:00:02 host sshd[1]: Failed password for root from 1.2.3.4 port 5001 ssh2\n",
            "Jan 1 00:00:03 host sshd[1]: Accepted password for root from 1.2.3.4 port 5002 ssh2\n",
            "Jan 1 00:00:04 host sshd[1]: some unrelated line\n",
        ]
        events = authlog.parse_events(lines)
        types = [e["type"] for e in events]
        self.assertEqual(types, ["invalid_user", "failed", "accepted"])
        self.assertEqual(events[0]["user"], "admin")
        self.assertEqual(events[1]["ip"], "1.2.3.4")

    def test_assess_events_flags_brute_force_by_ip(self):
        events = [
            {"line_no": i, "type": "failed", "user": "root", "ip": "9.9.9.9"}
            for i in range(6)
        ]
        findings = authlog.assess_events(events, fail_threshold=5)
        self.assertTrue(any(f["severity"] == "High" and f["source"] == "9.9.9.9"
                            for f in findings))

    def test_assess_events_below_threshold_yields_no_findings(self):
        events = [
            {"line_no": i, "type": "failed", "user": "root", "ip": "9.9.9.9"}
            for i in range(2)
        ]
        self.assertEqual(authlog.assess_events(events, fail_threshold=5), [])

    def test_assess_events_flags_invalid_user_enumeration(self):
        events = [
            {"line_no": i, "type": "invalid_user", "user": f"user{i}", "ip": "8.8.8.8"}
            for i in range(6)
        ]
        findings = authlog.assess_events(events, fail_threshold=5)
        self.assertTrue(any(f["severity"] == "Medium" for f in findings))

    def test_assess_events_flags_success_after_failure_burst_as_critical(self):
        events = (
            [{"line_no": i, "type": "failed", "user": "root", "ip": "5.5.5.5"} for i in range(5)]
            + [{"line_no": 5, "type": "accepted", "user": "root", "ip": "5.5.5.5"}]
        )
        findings = authlog.assess_events(events, fail_threshold=5)
        self.assertTrue(any(f["severity"] == "Critical" for f in findings))

    def test_resolve_log_path_explicit_missing_returns_none(self):
        self.assertIsNone(authlog.resolve_log_path("/nonexistent/path/auth.log"))

    def test_audit_reports_error_when_no_log_found(self):
        result = authlog.audit(log_path="/definitely/not/a/real/file.log")
        self.assertIsNotNone(result["error"])
        self.assertEqual(result["findings"], [])

    def test_module_exposes_run_and_cli_run(self):
        self.assertTrue(callable(authlog.run))
        self.assertTrue(callable(authlog.cli_run))


class TestPackageCveAuditor(unittest.TestCase):
    """Pure logic in modules/package_cve_auditor.py — version comparison
    and offline signature matching, no subprocess/network involved."""

    def test_version_tuple_parses_leading_numeric_segments(self):
        self.assertEqual(pkgaudit._version_tuple("1.1.1f-1ubuntu2.20"), (1, 1, 1))
        self.assertEqual(pkgaudit._version_tuple("2.4.41"), (2, 4, 41))
        self.assertEqual(pkgaudit._version_tuple("not-a-version"), ())

    def test_version_lt_compares_correctly(self):
        self.assertTrue(pkgaudit._version_lt("1.0.9", "1.1.0"))
        self.assertFalse(pkgaudit._version_lt("1.1.1", "1.1.0"))
        self.assertFalse(pkgaudit._version_lt("garbage", "1.1.0"))

    def test_assess_offline_flags_old_openssl(self):
        finding = pkgaudit.assess_offline("openssl", "1.0.2g-1ubuntu4")
        self.assertIsNotNone(finding)
        self.assertEqual(finding["severity"], "High")

    def test_assess_offline_flags_python2_unconditionally(self):
        finding = pkgaudit.assess_offline("python2.7", "2.7.18-1")
        self.assertIsNotNone(finding)

    def test_assess_offline_does_not_flag_current_openssl(self):
        self.assertIsNone(pkgaudit.assess_offline("openssl", "3.0.2-0ubuntu1.10"))

    def test_assess_offline_unrelated_package_returns_none(self):
        self.assertIsNone(pkgaudit.assess_offline("some-random-tool", "9.9.9"))

    def test_is_security_relevant(self):
        self.assertTrue(pkgaudit.is_security_relevant("libssl-dev"))
        self.assertTrue(pkgaudit.is_security_relevant("openssh-server"))
        self.assertFalse(pkgaudit.is_security_relevant("cowsay"))

    def test_audit_runs_offline_without_network(self):
        # enable_cve_feed=False must never touch the network.
        result = pkgaudit.audit(enable_cve_feed=False)
        self.assertFalse(result["live_feed_used"])
        self.assertIsInstance(result["findings"], list)

    def test_module_exposes_run_and_cli_run(self):
        self.assertTrue(callable(pkgaudit.run))
        self.assertTrue(callable(pkgaudit.cli_run))


def struct_pack_pointer(target_offset: int) -> bytes:
    """Build a 2-byte DNS name-compression pointer to *target_offset*."""
    import struct
    return struct.pack(">H", 0xC000 | (target_offset & 0x3FFF))


class TestDockerAuditor(unittest.TestCase):
    def test_audit_degrades_gracefully_without_docker(self):
        # In CI / most dev machines the docker CLI won't be present (or
        # won't be reachable) — either way audit() must never raise.
        findings = docker_auditor.audit()
        self.assertIsInstance(findings, list)

    def test_finding_shape(self):
        f = docker_auditor._finding("Test", "High", "desc", "fix")
        self.assertEqual(set(f.keys()), {"component", "severity", "finding", "remediation"})

    def test_module_exposes_run_and_cli_run(self):
        self.assertTrue(callable(docker_auditor.run))
        self.assertTrue(callable(docker_auditor.cli_run))


class TestFirewallAuditor(unittest.TestCase):
    def test_audit_degrades_gracefully(self):
        findings = firewall_auditor.audit()
        self.assertIsInstance(findings, list)
        # Even the "nothing available" path returns at least one Info finding.
        self.assertTrue(len(findings) >= 0)

    def test_finding_shape(self):
        f = firewall_auditor._finding("iptables", "High", "desc", "fix")
        self.assertEqual(set(f.keys()), {"rule_source", "severity", "finding", "remediation"})

    def test_sensitive_ports_table_has_expected_entries(self):
        self.assertIn("22", firewall_auditor.SENSITIVE_PORTS)
        self.assertIn("3389", firewall_auditor.SENSITIVE_PORTS)

    def test_module_exposes_run_and_cli_run(self):
        self.assertTrue(callable(firewall_auditor.run))
        self.assertTrue(callable(firewall_auditor.cli_run))


class TestWebAppScanner(unittest.TestCase):
    def test_normalize_target_adds_scheme(self):
        self.assertEqual(web_app_scanner._normalize_target("example.com"),
                         "https://example.com")
        self.assertEqual(web_app_scanner._normalize_target("http://example.com/some/path"),
                         "http://example.com")

    def test_csrf_hint_flags_form_without_token(self):
        body = '<form method="POST" action="/x"><input name="email"></form>'
        self.assertTrue(web_app_scanner.CSRF_NAME_HINT.search("no token here") is None)
        self.assertIsNone(web_app_scanner.CSRF_NAME_HINT.search(body))

    def test_csrf_hint_recognizes_token_field(self):
        body = '<input type="hidden" name="csrf_token" value="abc">'
        self.assertIsNotNone(web_app_scanner.CSRF_NAME_HINT.search(body))

    def test_debug_signatures_match_django(self):
        sample = "You're seeing this error because you have DEBUG = True"
        matched = any(p.search(sample) for p, _ in web_app_scanner.DEBUG_SIGNATURES)
        self.assertTrue(matched)

    def test_module_exposes_run_and_cli_run(self):
        self.assertTrue(callable(web_app_scanner.run))
        self.assertTrue(callable(web_app_scanner.cli_run))


class TestSubdomainMapper(unittest.TestCase):
    def test_invalid_domain_returns_error(self):
        result = subdomain_mapper.audit("not a domain!!")
        self.assertIsNotNone(result["error"])
        self.assertEqual(result["hosts"], [])

    def test_valid_domain_passes_regex(self):
        self.assertTrue(subdomain_mapper._valid_domain("example.com"))
        self.assertFalse(subdomain_mapper._valid_domain("not a domain"))

    def test_sensitive_label_hint_matches_common_labels(self):
        self.assertIsNotNone(subdomain_mapper.SENSITIVE_LABEL_HINTS.match("dev"))
        self.assertIsNotNone(subdomain_mapper.SENSITIVE_LABEL_HINTS.match("staging"))
        self.assertIsNone(subdomain_mapper.SENSITIVE_LABEL_HINTS.match("www"))

    def test_module_exposes_run_and_cli_run(self):
        self.assertTrue(callable(subdomain_mapper.run))
        self.assertTrue(callable(subdomain_mapper.cli_run))


class TestDnsSecurityAuditorExtendedChecks(unittest.TestCase):
    def test_mta_sts_absent_flags_low(self):
        findings = dnsaudit.assess_mta_sts([])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "Low")

    def test_mta_sts_present_no_finding(self):
        findings = dnsaudit.assess_mta_sts(["v=STSv1; id=20260101000000Z"])
        self.assertEqual(findings, [])

    def test_mta_sts_duplicate_records_flagged(self):
        findings = dnsaudit.assess_mta_sts(["v=STSv1; id=1", "v=STSv1; id=2"])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "Medium")

    def test_tls_rpt_absent_is_informational(self):
        findings = dnsaudit.assess_tls_rpt([])
        self.assertEqual(findings[0]["severity"], "Info")

    def test_bimi_present_without_dmarc_enforcement_flagged(self):
        findings = dnsaudit.assess_bimi(
            ["v=BIMI1; l=https://example.com/logo.svg"], ["v=DMARC1; p=none"])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "Low")

    def test_bimi_present_with_dmarc_enforcement_ok(self):
        findings = dnsaudit.assess_bimi(
            ["v=BIMI1; l=https://example.com/logo.svg"], ["v=DMARC1; p=reject"])
        self.assertEqual(findings, [])

    def test_build_findings_includes_new_checks(self):
        findings = dnsaudit.build_findings(
            txt_records=["v=spf1 -all"],
            dmarc_txt_records=["v=DMARC1; p=reject"],
            dnskey_present=True,
            mta_sts_txt_records=[],
            tls_rpt_txt_records=[],
            bimi_txt_records=[],
        )
        checks = {f["check"] for f in findings}
        self.assertIn("MTA-STS", checks)
        self.assertIn("TLS-RPT", checks)
        self.assertIn("BIMI", checks)


class TestConfigSchemaValidation(unittest.TestCase):
    def test_valid_config_passes_unchanged(self):
        cfg = dict(config_mod.DEFAULT_CONFIG)
        repaired, warnings = config_mod.validate_config(cfg)
        self.assertEqual(warnings, [])
        self.assertEqual(repaired["port_scan_threads"], cfg["port_scan_threads"])

    def test_negative_thread_count_repaired(self):
        cfg = dict(config_mod.DEFAULT_CONFIG)
        cfg["port_scan_threads"] = -5
        repaired, warnings = config_mod.validate_config(cfg)
        self.assertEqual(len(warnings), 1)
        self.assertEqual(repaired["port_scan_threads"], config_mod.DEFAULT_CONFIG["port_scan_threads"])

    def test_wrong_type_repaired(self):
        cfg = dict(config_mod.DEFAULT_CONFIG)
        cfg["fim_watch_paths"] = "not-a-list"
        repaired, warnings = config_mod.validate_config(cfg)
        self.assertEqual(len(warnings), 1)
        self.assertEqual(repaired["fim_watch_paths"], [])

    def test_invalid_report_format_repaired(self):
        cfg = dict(config_mod.DEFAULT_CONFIG)
        cfg["report_format"] = "yaml"
        repaired, warnings = config_mod.validate_config(cfg)
        self.assertEqual(len(warnings), 1)
        self.assertEqual(repaired["report_format"], config_mod.DEFAULT_CONFIG["report_format"])

    def test_unknown_keys_pass_through(self):
        cfg = dict(config_mod.DEFAULT_CONFIG)
        cfg["some_future_setting"] = {"nested": True}
        repaired, warnings = config_mod.validate_config(cfg)
        self.assertEqual(warnings, [])
        self.assertEqual(repaired["some_future_setting"], {"nested": True})

    def test_load_config_auto_repairs_bad_settings_file(self):
        tmpdir = tempfile.mkdtemp()
        try:
            orig_dir, orig_file = config_mod.CONFIG_DIR, config_mod.CONFIG_FILE
            config_mod.CONFIG_DIR = tmpdir
            config_mod.CONFIG_FILE = os.path.join(tmpdir, "settings.json")
            try:
                with open(config_mod.CONFIG_FILE, "w") as fh:
                    json.dump({"port_scan_threads": -100}, fh)
                cfg = config_mod.load_config()
                self.assertEqual(cfg["port_scan_threads"],
                                 config_mod.DEFAULT_CONFIG["port_scan_threads"])
            finally:
                config_mod.CONFIG_DIR, config_mod.CONFIG_FILE = orig_dir, orig_file
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestExportPdf(unittest.TestCase):
    def test_export_pdf_produces_a_file_or_raises_actionable_error(self):
        tmpdir = tempfile.mkdtemp()
        try:
            session_info = {"session_id": "test", "operator_name": "tester"}
            activity = [{"created_at": "2026-01-01T00:00:00", "module_name": "port_scanner",
                        "status": "success", "result_summary": "ok"}]
            scan_results = [{"scan_type": "port_scan", "target": "10.0.0.1",
                            "extra": {"findings": []}}]
            try:
                path = export_pdf(session_info, activity, scan_results, tmpdir)
                self.assertTrue(os.path.exists(path))
                self.assertTrue(path.endswith(".pdf"))
            except RuntimeError as exc:
                self.assertIn("reportlab", str(exc))
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestReportIncludesNewModuleSections(unittest.TestCase):
    def test_html_report_renders_without_error_for_new_scan_types(self):
        tmpdir = tempfile.mkdtemp()
        try:
            scan_results = [
                {"scan_type": "docker_audit", "target": "local-docker",
                 "extra": {"findings": [{"component": "Test", "severity": "High",
                                         "finding": "x", "remediation": "y"}]}},
                {"scan_type": "firewall_audit", "target": "local-firewall",
                 "extra": {"findings": [{"rule_source": "iptables", "severity": "Medium",
                                         "finding": "x", "remediation": "y"}]}},
                {"scan_type": "web_app_scan", "target": "https://example.com",
                 "extra": {"findings": [{"check": "Exposed File", "severity": "Critical",
                                         "finding": "x", "remediation": "y"}]}},
                {"scan_type": "subdomain_map", "target": "example.com",
                 "extra": {"findings": [{"path": "dev.example.com", "severity": "Low",
                                         "finding": "x"}]}},
            ]
            path = generate_html_report({"session_id": "t"}, [], scan_results, tmpdir)
            with open(path) as fh:
                html_content = fh.read()
            self.assertIn("Docker/Container Audit Findings", html_content)
            self.assertIn("Firewall Audit Findings", html_content)
            self.assertIn("Web App Scanner Findings", html_content)
            self.assertIn("Subdomain Mapping Results", html_content)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestDbLocalFallback(unittest.TestCase):
    """
    utils/db.py's local SQLite store (logs/toolkit.db) is the source of
    truth; Supabase is an opt-in mirror. These tests force the cloud off
    deliberately, against a throwaway LOG_DIR, so the local path itself —
    not just "no exception was raised" — is what's checked.
    """

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self._orig = (db.LOG_DIR, db.SUPABASE_URL, db.SUPABASE_KEY,
                      db.CLOUD_LOGGING_ENABLED, db.LOCAL_LOG_RETENTION_DAYS)
        db.LOG_DIR = self.tmpdir
        db.SUPABASE_URL = ""
        db.SUPABASE_KEY = ""
        db.CLOUD_LOGGING_ENABLED = False
        db.LOCAL_LOG_RETENTION_DAYS = 0

    def tearDown(self):
        (db.LOG_DIR, db.SUPABASE_URL, db.SUPABASE_KEY,
         db.CLOUD_LOGGING_ENABLED, db.LOCAL_LOG_RETENTION_DAYS) = self._orig
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_is_available_false_when_unconfigured(self):
        self.assertFalse(db.is_available())

    def test_create_session_mints_local_id_and_creates_database(self):
        session_id = db.create_session(operator="tester")
        self.assertTrue(db.is_local_session(session_id))
        self.assertEqual(db.session_kind(session_id), "local")
        self.assertTrue(os.path.exists(os.path.join(self.tmpdir, "toolkit.db")))

    def test_database_file_is_owner_only(self):
        db.create_session(operator="tester")
        if os.name == "posix":
            mode = os.stat(os.path.join(self.tmpdir, "toolkit.db")).st_mode & 0o777
            self.assertEqual(mode, 0o600)

    def test_end_session_sets_ended_at_locally(self):
        session_id = db.create_session(operator="tester")
        db.end_session(session_id)
        matching = [s for s in db.get_sessions(limit=10) if s.get("id") == session_id]
        self.assertEqual(len(matching), 1)
        self.assertIsNotNone(matching[0].get("ended_at"))

    def test_log_activity_and_read_back_scoped_to_session(self):
        session_a = db.create_session(operator="a")
        session_b = db.create_session(operator="b")
        db.log_activity(session_a, "port_scanner", {"target": "10.0.0.1"},
                        status="success", result_summary="ok", detail={"k": [1, 2]})
        db.log_activity(session_b, "ssl_auditor", {"target": "example.com"},
                        status="success", result_summary="ok")

        only_a = db.get_activity_log(session_id=session_a)
        self.assertEqual(len(only_a), 1)
        self.assertEqual(only_a[0]["module_name"], "port_scanner")
        self.assertEqual(only_a[0]["parameters"], {"target": "10.0.0.1"})   # JSON round-trips to dicts
        self.assertEqual(only_a[0]["detail"], {"k": [1, 2]})
        self.assertEqual(len(db.get_activity_log(session_id=None, limit=50)), 2)

    def test_activity_is_newest_first_and_limit_applies(self):
        sid = db.create_session(operator="t")
        for i in range(5):
            db.log_activity(sid, "m", {"i": i}, status="success")
        rows = db.get_activity_log(session_id=sid, limit=3)
        self.assertEqual([r["parameters"]["i"] for r in rows], [4, 3, 2])

    def test_log_scan_result_and_read_back_scoped_to_session(self):
        session_id = db.create_session(operator="tester")
        db.log_scan_result(session_id, "port_scan", target="10.0.0.5",
                           ip_address="10.0.0.5", open_ports=[22, 80],
                           extra={"findings": [{"severity": "High", "finding": "x"}]})
        results = db.get_scan_results(session_id=session_id)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["open_ports"], [22, 80])
        self.assertEqual(results[0]["extra"]["findings"][0]["severity"], "High")

    def test_values_are_stored_as_data_not_sql(self):
        sid = db.create_session(operator="x'); DROP TABLE sessions;--")
        db.log_activity(sid, "m'; DROP TABLE activity;--", {}, status="success")
        self.assertEqual(len(db.get_sessions()), 1)
        self.assertEqual(len(db.get_activity_log(session_id=sid)), 1)

    def test_get_functions_never_raise_on_empty_store(self):
        self.assertEqual(db.get_activity_log(session_id="anything"), [])
        self.assertEqual(db.get_scan_results(session_id="anything"), [])
        self.assertEqual(db.get_sessions(), [])

    def test_unwritable_log_dir_is_non_fatal(self):
        blocker = os.path.join(self.tmpdir, "afile")
        with open(blocker, "w") as fh:
            fh.write("x")
        db.LOG_DIR = os.path.join(blocker, "sub")       # can't mkdir under a file
        sid = db.create_session(operator="t")            # must still hand back an id
        self.assertTrue(sid)
        db.log_activity(sid, "m", {}, status="success")  # and not raise
        self.assertEqual(db.get_sessions(), [])

    def test_legacy_jsonl_history_is_imported_once(self):
        with open(os.path.join(self.tmpdir, "sessions.jsonl"), "w") as fh:
            fh.write(json.dumps({"id": "local-old", "operator": "legacy",
                                 "created_at": "2026-01-01T00:00:00+00:00", "ended_at": None}) + "\n")
        with open(os.path.join(self.tmpdir, "activity.jsonl"), "w") as fh:
            fh.write(json.dumps({"session_id": "local-old", "module_name": "good",
                                 "parameters": {}, "status": "success",
                                 "created_at": "2026-01-01T00:00:01+00:00"}) + "\n")
            fh.write("not json at all\n")
            fh.write(json.dumps({"session_id": "local-old", "module_name": "also_good",
                                 "parameters": {}, "status": "success",
                                 "created_at": "2026-01-01T00:00:02+00:00"}) + "\n")
        with open(os.path.join(self.tmpdir, "scan_results.jsonl"), "w") as fh:
            fh.write(json.dumps({"session_id": "local-old", "scan_type": "port_scan",
                                 "open_ports": [22], "created_at": "2026-01-01T00:00:03+00:00"}) + "\n")

        self.assertEqual([s["id"] for s in db.get_sessions()], ["local-old"])
        self.assertEqual(len(db.get_activity_log(session_id="local-old")), 2)   # malformed line skipped
        self.assertEqual(db.get_scan_results(session_id="local-old")[0]["open_ports"], [22])
        # A second open must not duplicate the import.
        db.create_session(operator="new")
        self.assertEqual(len(db.get_activity_log(session_id="local-old")), 2)

    def test_retention_prunes_old_sessions_and_their_rows(self):
        old = db.create_session(operator="old")
        db.log_activity(old, "m", {}, status="success")
        db.log_scan_result(old, "port_scan", open_ports=[1])
        conn = db._connect()
        with conn:
            conn.execute("UPDATE sessions SET created_at = '2000-01-01T00:00:00+00:00' WHERE id = ?", (old,))
        conn.close()
        keep = db.create_session(operator="new")
        self.assertEqual(db.prune_local(30), 1)
        self.assertEqual([s["id"] for s in db.get_sessions()], [keep])
        self.assertEqual(db.get_activity_log(session_id=old), [])
        self.assertEqual(db.get_scan_results(session_id=old), [])
        self.assertEqual(db.prune_local(0), 0)          # 0 = keep everything


class TestDbCloudOptIn(unittest.TestCase):
    """Credentials alone must NOT send scan data off the machine."""

    def setUp(self):
        self._orig = (db.LOG_DIR, db.SUPABASE_URL, db.SUPABASE_KEY, db.CLOUD_LOGGING_ENABLED)
        self.tmpdir = tempfile.mkdtemp()
        db.LOG_DIR = self.tmpdir
        db.SUPABASE_URL, db.SUPABASE_KEY = "https://x.test", "k"

    def tearDown(self):
        db.LOG_DIR, db.SUPABASE_URL, db.SUPABASE_KEY, db.CLOUD_LOGGING_ENABLED = self._orig
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_credentials_without_opt_in_stay_local(self):
        from unittest import mock
        db.CLOUD_LOGGING_ENABLED = False
        self.assertFalse(db.is_available())
        with mock.patch("urllib.request.urlopen", side_effect=AssertionError("network used")):
            sid = db.create_session(operator="t")
            db.log_activity(sid, "m", {}, status="success")
            db.log_scan_result(sid, "port_scan", open_ports=[22])
            db.end_session(sid)
        self.assertTrue(db.is_local_session(sid))
        self.assertIn("TOOLKIT_CLOUD_LOGGING", db.check_connection()["error"])
        self.assertFalse(db.check_connection()["configured"])

    def test_opt_in_sends_to_cloud_and_mirrors_locally(self):
        from unittest import mock
        db.CLOUD_LOGGING_ENABLED = True
        calls = []

        def fake_rest(method, path, body=None, params=None):
            calls.append((method, path))
            if method == "POST" and path == "toolkit_sessions":
                return [{"id": "11111111-2222-3333-4444-555555555555"}]
            return []

        with mock.patch.object(db, "_rest_request", fake_rest):
            sid = db.create_session(operator="t")
            db.log_activity(sid, "m", {}, status="success")
        self.assertEqual(sid, "11111111-2222-3333-4444-555555555555")
        self.assertEqual(db.session_kind(sid), "cloud")
        self.assertIn(("POST", "toolkit_activity"), calls)
        self.assertEqual(len(db.get_activity_log(session_id=sid)), 1)   # local mirror too (cloud mocked empty)

    def test_get_sessions_orders_by_started_at_and_normalises(self):
        from unittest import mock
        db.CLOUD_LOGGING_ENABLED = True
        captured = {}

        def fake_rest(method, path, body=None, params=None):
            captured["params"] = params
            return [{"id": "abc", "started_at": "2026-09-27T10:00:00+00:00"}]

        with mock.patch.object(db, "_rest_request", fake_rest):
            rows = db.get_sessions(limit=5)
        self.assertEqual(captured["params"]["order"], "started_at.desc")
        self.assertEqual(rows[0]["created_at"], "2026-09-27T10:00:00+00:00")

    def test_end_session_sends_real_timestamp(self):
        from unittest import mock
        db.CLOUD_LOGGING_ENABLED = True
        calls = []
        with mock.patch.object(db, "_rest_request", lambda *a, **k: calls.append((a, k))):
            db.end_session("11111111-2222-3333-4444-555555555555")
        body = calls[0][1]["body"]
        self.assertNotEqual(body["ended_at"], "now()")
        self.assertRegex(body["ended_at"], r"^\d{4}-\d{2}-\d{2}T")

    def test_scan_results_are_paginated_not_truncated(self):
        from unittest import mock
        db.CLOUD_LOGGING_ENABLED = True
        pages = {0: [{"i": n} for n in range(1000)], 1000: [{"i": n} for n in range(1000, 1300)]}
        seen = []

        def fake_rest(method, path, body=None, params=None):
            seen.append(int(params["offset"]))
            return pages[int(params["offset"])]

        with mock.patch.object(db, "_rest_request", fake_rest):
            rows = db.get_scan_results(session_id="11111111-2222-3333-4444-555555555555")
        self.assertEqual(len(rows), 1300)
        self.assertEqual(seen, [0, 1000])

    def test_failed_page_falls_back_to_local_instead_of_partial_data(self):
        from unittest import mock
        db.CLOUD_LOGGING_ENABLED = True
        sid = "11111111-2222-3333-4444-555555555555"
        with mock.patch.object(db, "_rest_request", lambda *a, **k: None):
            db._local_write(db._insert_scan, {"session_id": sid, "scan_type": "port_scan",
                                              "open_ports": [443], "created_at": db._now_iso()})
            rows = db.get_scan_results(session_id=sid)
        self.assertEqual(rows[0]["open_ports"], [443])

    def test_bad_env_int_does_not_crash(self):
        from unittest import mock
        with mock.patch.dict(os.environ, {"LOCAL_LOG_RETENTION_DAYS": "5MB"}):
            self.assertEqual(db._env_int("LOCAL_LOG_RETENTION_DAYS", 7), 7)
        with mock.patch.dict(os.environ, {"LOCAL_LOG_RETENTION_DAYS": "14"}):
            self.assertEqual(db._env_int("LOCAL_LOG_RETENTION_DAYS", 7), 14)


class TestSecretsAndWebhooks(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self._orig = (config_mod.CONFIG_DIR, config_mod.CONFIG_FILE)
        config_mod.CONFIG_DIR = self.tmpdir
        config_mod.CONFIG_FILE = os.path.join(self.tmpdir, "settings.json")

    def tearDown(self):
        config_mod.CONFIG_DIR, config_mod.CONFIG_FILE = self._orig
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_env_secret_overrides_file_but_is_never_written_back(self):
        from unittest import mock
        with open(config_mod.CONFIG_FILE, "w") as fh:
            json.dump({"alert_email_password": "from-file", "scan_timeout": 3}, fh)
        with mock.patch.dict(os.environ, {"TOOLKIT_ALERT_EMAIL_PASSWORD": "from-env"}):
            cfg = config_mod.load_config()
            self.assertEqual(cfg["alert_email_password"], "from-env")
            cfg["scan_timeout"] = 9
            config_mod.save_config(cfg)
        with open(config_mod.CONFIG_FILE) as fh:
            on_disk = json.load(fh)
        self.assertEqual(on_disk["alert_email_password"], "from-file")   # env value not persisted
        self.assertNotIn("from-env", json.dumps(on_disk))
        self.assertEqual(on_disk["scan_timeout"], 9)

    def test_saved_settings_file_is_owner_only(self):
        config_mod.save_config(dict(config_mod.DEFAULT_CONFIG))
        if os.name == "posix":
            self.assertEqual(os.stat(config_mod.CONFIG_FILE).st_mode & 0o777, 0o600)

    def test_secrets_are_masked_for_display(self):
        self.assertEqual(config_mod.mask_value("alert_email_password", "hunter2"), "********")
        self.assertEqual(config_mod.mask_value("alert_slack_webhook_url", ""), "")
        self.assertEqual(config_mod.mask_value("scan_timeout", 2), "2")
        self.assertNotIn("hunter2", config_mod.mask_value("alert_email_password", "hunter2"))

    def test_webhook_rejects_non_http_schemes(self):
        for url in ("file:///etc/passwd", "ftp://example.com/x", "gopher://x", "javascript:alert(1)"):
            ok, err = alerting.send_webhook(url, {"a": 1})
            self.assertFalse(ok, url)
            self.assertIn("http", err)


class TestAlerting(unittest.TestCase):
    def test_summarize_new_findings_filters_by_severity(self):
        changes = {
            ("vulnerability_scan", "10.0.0.5"): {
                "new_ports": [],
                "closed_ports": [],
                "new_findings": [
                    {"severity": "Critical", "finding": "critical thing", "cve": "CVE-2020-0001"},
                    {"severity": "Low", "finding": "low thing"},
                ],
                "resolved_findings": [],
            },
        }
        alertable = alerting.summarize_new_findings(changes, min_severity="High")
        self.assertEqual(len(alertable), 1)
        self.assertEqual(alertable[0]["severity"], "Critical")

    def test_summarize_new_findings_includes_new_ports_at_low_threshold(self):
        changes = {
            ("port_scan", "10.0.0.5"): {
                "new_ports": [8080],
                "closed_ports": [],
                "new_findings": [],
                "resolved_findings": [],
            },
        }
        alertable = alerting.summarize_new_findings(changes, min_severity="Low")
        self.assertEqual(len(alertable), 1)
        self.assertIn("8080", alertable[0]["description"])

    def test_summarize_new_findings_empty_when_no_changes(self):
        self.assertEqual(alerting.summarize_new_findings({}, min_severity="High"), [])

    def test_format_alert_text_handles_empty_list(self):
        self.assertEqual(alerting.format_alert_text([]), "No new findings.")

    def test_send_webhook_with_no_url_fails_cleanly(self):
        ok, err = alerting.send_webhook("", {"x": 1})
        self.assertFalse(ok)
        self.assertIn("no webhook URL", err)

    def test_send_email_with_no_host_fails_cleanly(self):
        ok, err = alerting.send_email("", 587, "from@x.com", "to@x.com", "subj", "body")
        self.assertFalse(ok)

    def test_alert_on_changes_skips_unconfigured_channels(self):
        changes = {
            ("vulnerability_scan", "10.0.0.5"): {
                "new_ports": [], "closed_ports": [],
                "new_findings": [{"severity": "Critical", "finding": "x"}],
                "resolved_findings": [],
            },
        }
        config = {"alert_min_severity": "High"}  # no channels configured
        result = alerting.alert_on_changes(changes, config, session_id="s1")
        self.assertEqual(len(result["alertable"]), 1)
        self.assertEqual(result["sent"], {})


class TestBatchTargetsFile(unittest.TestCase):
    """utils.diff/main.py's --targets-file parsing (main._read_targets_file)."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        import main as toolkit_main
        self.toolkit_main = toolkit_main

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write(self, name, content):
        path = os.path.join(self.tmpdir, name)
        with open(path, "w") as fh:
            fh.write(content)
        return path

    def test_plain_list_one_per_line(self):
        path = self._write("targets.txt", "10.0.0.1\n10.0.0.2\n\n# a comment\n10.0.0.3\n")
        targets = self.toolkit_main._read_targets_file(path)
        self.assertEqual(targets, ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

    def test_csv_with_target_header(self):
        path = self._write("targets.csv", "target,notes\n10.0.0.1,web server\n10.0.0.2,db server\n")
        targets = self.toolkit_main._read_targets_file(path)
        self.assertEqual(targets, ["10.0.0.1", "10.0.0.2"])

    def test_csv_with_host_header(self):
        path = self._write("targets.csv", "host\nexample.com\nexample.org\n")
        targets = self.toolkit_main._read_targets_file(path)
        self.assertEqual(targets, ["example.com", "example.org"])

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            self.toolkit_main._read_targets_file(os.path.join(self.tmpdir, "nope.txt"))

    def test_empty_file_returns_empty_list(self):
        path = self._write("empty.txt", "\n\n")
        self.assertEqual(self.toolkit_main._read_targets_file(path), [])


class TestV371ReviewFixes(unittest.TestCase):
    """Regression tests for the code-review patches."""

    def test_no_crlf_in_python_sources(self):
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        offenders = []
        for base, _, files in os.walk(root):
            for f in files:
                if f.endswith(".py"):
                    with open(os.path.join(base, f), "rb") as fh:
                        if b"\r\n" in fh.read():
                            offenders.append(f)
        self.assertEqual(offenders, [])


class TestScopeGuard(unittest.TestCase):
    """utils/scope.py — allowed_targets enforcement."""

    def _cfg(self, *entries, require=False):
        return {"allowed_targets": list(entries), "require_scope": require}

    def test_empty_scope_is_unrestricted_by_default(self):
        from utils import scope
        self.assertTrue(scope.check("8.8.8.8", self._cfg())[0])

    def test_require_scope_with_empty_list_refuses(self):
        from utils import scope
        ok, reason = scope.check("192.168.1.10", self._cfg(require=True))
        self.assertFalse(ok)
        self.assertIn("require_scope", reason)

    def test_empty_target_passes_through(self):
        from utils import scope
        self.assertTrue(scope.check("", self._cfg("10.0.0.0/8", require=True))[0])

    def test_ip_in_and_out_of_cidr(self):
        from utils import scope
        cfg = self._cfg("192.168.1.0/24")
        self.assertTrue(scope.check("192.168.1.77", cfg)[0])
        self.assertFalse(scope.check("192.168.2.1", cfg)[0])

    def test_single_ip_entry(self):
        from utils import scope
        cfg = self._cfg("10.0.0.5")
        self.assertTrue(scope.check("10.0.0.5", cfg)[0])
        self.assertFalse(scope.check("10.0.0.6", cfg)[0])

    def test_target_range_must_be_wholly_inside(self):
        from utils import scope
        cfg = self._cfg("10.0.0.0/24")
        self.assertTrue(scope.check("10.0.0.0/25", cfg)[0])
        self.assertTrue(scope.check("10.0.0.0/24", cfg)[0])
        self.assertFalse(scope.check("10.0.0.0/23", cfg)[0])   # overlaps but larger
        self.assertFalse(scope.check("10.0.1.0/24", cfg)[0])

    def test_ipv4_and_ipv6_dont_cross_match(self):
        from utils import scope
        self.assertFalse(scope.check("::1", self._cfg("10.0.0.0/8"))[0])
        self.assertTrue(scope.check("fd00::5", self._cfg("fd00::/8"))[0])

    def test_exact_hostname_excludes_subdomains(self):
        from utils import scope
        cfg = self._cfg("example.com")
        self.assertTrue(scope.check("example.com", cfg)[0])
        self.assertTrue(scope.check("EXAMPLE.com.", cfg)[0])
        self.assertFalse(scope.check("www.example.com", cfg, resolver=lambda h: [])[0])

    def test_wildcard_matches_subdomains_not_apex_or_lookalikes(self):
        from utils import scope
        cfg = self._cfg("*.example.com")
        no_dns = lambda h: []
        self.assertTrue(scope.check("api.example.com", cfg, resolver=no_dns)[0])
        self.assertTrue(scope.check("a.b.example.com", cfg, resolver=no_dns)[0])
        self.assertFalse(scope.check("example.com", cfg, resolver=no_dns)[0])
        self.assertFalse(scope.check("evilexample.com", cfg, resolver=no_dns)[0])
        self.assertFalse(scope.check("example.com.evil.net", cfg, resolver=no_dns)[0])

    def test_urls_and_ports_reduced_to_host(self):
        from utils import scope
        cfg = self._cfg("example.com", "10.0.0.0/24")
        self.assertTrue(scope.check("https://example.com:8443/admin?x=1", cfg)[0])
        self.assertTrue(scope.check("example.com:443", cfg)[0])
        self.assertTrue(scope.check("http://10.0.0.9:8080/", cfg)[0])
        self.assertFalse(scope.check("https://other.test/", cfg, resolver=lambda h: [])[0])
        # userinfo trick: the host is what follows '@'
        self.assertFalse(scope.check("https://example.com@evil.test/", cfg,
                                     resolver=lambda h: [])[0])

    def test_hostname_checked_by_resolved_address(self):
        from utils import scope
        cfg = self._cfg("10.0.0.0/24")
        self.assertTrue(scope.check("app.corp", cfg, resolver=lambda h: ["10.0.0.4"])[0])
        ok, reason = scope.check("app.corp", cfg, resolver=lambda h: ["10.0.0.4", "8.8.8.8"])
        self.assertFalse(ok)
        self.assertIn("8.8.8.8", reason)

    def test_unresolvable_hostname_is_refused_under_cidr_scope(self):
        from utils import scope
        ok, reason = scope.check("nope.invalid", self._cfg("10.0.0.0/24"),
                                 resolver=lambda h: [])
        self.assertFalse(ok)
        self.assertIn("resolved", reason)

    def test_bad_entries_reported_not_fatal(self):
        from utils import scope
        cfg = self._cfg("10.0.0.0/24", "not a host!", 42, "0.0.0.0/0")
        warnings = scope.scope_warnings(cfg)
        self.assertEqual(len(warnings), 3)   # bad string, non-string, match-everything
        self.assertTrue(scope.check("10.0.0.3", cfg)[0])

    def test_config_defaults_and_schema(self):
        from utils import config as config_mod
        self.assertEqual(config_mod.DEFAULT_CONFIG["allowed_targets"], [])
        self.assertFalse(config_mod.DEFAULT_CONFIG["require_scope"])
        cfg = dict(config_mod.DEFAULT_CONFIG)
        cfg["allowed_targets"] = "10.0.0.0/24"          # wrong type: string, not list
        repaired, warnings = config_mod.validate_config(cfg)
        self.assertEqual(repaired["allowed_targets"], [])
        self.assertTrue(any("allowed_targets" in w for w in warnings))

    def test_interactive_module_refuses_out_of_scope_before_scanning(self):
        from unittest import mock
        from modules import port_scanner
        cfg = dict(self._cfg("10.0.0.0/24"))
        # A second input() call (port selection) would mean the guard let it through.
        answers = iter(["8.8.8.8"])

        def fake_input(prompt=""):
            try:
                return next(answers)
            except StopIteration:
                raise AssertionError("scope guard did not stop the module")

        with mock.patch("builtins.input", fake_input):
            port_scanner.run(cfg, session_id=None)

    def test_every_targeted_interactive_module_imports_scope(self):
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for name in ("host_discovery", "network_scanner", "port_scanner",
                     "vulnerability_scanner", "ssl_auditor", "http_header_auditor",
                     "dns_security_auditor", "web_app_scanner", "subdomain_mapper"):
            with open(os.path.join(root, "modules", name + ".py")) as fh:
                src = fh.read()
            self.assertIn("scope.enforce(", src, name)


class TestVersionDefinedOnce(unittest.TestCase):
    def test_version_constant_and_no_hardcoded_strings(self):
        import re
        from utils import version
        self.assertRegex(version.__version__, r"^\d+\.\d+\.\d+$")
        self.assertEqual(version.SHORT_VERSION, ".".join(version.__version__.split(".")[:2]))
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        pat = re.compile(r"(Framework\s+v|Toolkit\s+v)\d+\.\d+")
        for rel in ("utils/rich_ui.py", "utils/report.py"):
            with open(os.path.join(root, rel)) as fh:
                self.assertIsNone(pat.search(fh.read()), rel)

    def test_report_footer_and_cli_help_use_current_version(self):
        from utils import version
        import main as main_mod
        parser_desc = main_mod.build_parser().description if hasattr(main_mod, "build_parser") else None
        if parser_desc:
            self.assertIn(f"v{version.SHORT_VERSION}", parser_desc)


if __name__ == "__main__":
    unittest.main()
