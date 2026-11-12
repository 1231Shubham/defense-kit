# Architecture & Roadmap (v3.10)

## 1. Shape of the system today

```
            ┌────────────── entry points ──────────────┐
            │ main.py (menu + CLI)   scheduled_scan.py │   dashboard/app.py (read-only)
            └───────────────┬──────────────────────────┘             │
                            │ scope.check()  ← policy gate           │ token auth
                            ▼                                        │
                 utils/module_loader  ──►  modules/*  (MODULE_META + run/cli_run)
                            │                    │ findings: {severity, finding, remediation, …}
                            ▼                    ▼
                      utils/db  ◄── local SQLite (always) ──► Supabase mirror (opt-in)
                            │
        ┌───────────────────┼─────────────────────────────┐
        ▼                   ▼                             ▼
  utils/risk (+suppress)  utils/diff (trend)   utils/report · export · sarif · alerting
```

Design principles worth keeping: **local-first** data, **fail-soft** modules
(never crash a scheduled run), **policy gate before any packet** (scope),
**pure functions at the edges** (risk, diff, sarif, suppressions are I/O-free and
unit-tested offline).

## 2. What v3.9 adds

| Capability | Where | Why |
|---|---|---|
| SARIF 2.1.0 export (`report_format: sarif`) | `utils/sarif.py` | Findings land in GitHub/GitLab/Azure/SIEM triage with stable rule ids and fingerprints |
| Accepted-risk register with mandatory expiry | `utils/suppressions.py`, `config/suppressions.json` | Stops alert fatigue without hiding risk forever; suppressed ≠ deleted |
| HMAC-signed FIM baseline | `file_integrity_monitor.py`, `TOOLKIT_FIM_HMAC_KEY` | An attacker who edits the baseline now trips a Critical finding |
| Dashboard token auth + refusal of unauthenticated network binds | `dashboard/app.py`, `TOOLKIT_DASHBOARD_TOKEN` | Safe-by-default exposure |

`suppressions.json` entry:

```json
[{"match": "TLS 1.0", "target": "legacy.example.com",
  "reason": "Vendor appliance, replacement ticketed", "owner": "alice",
  "expires": "2026-12-31"}]
```

## 3. Roadmap (ordered by value ÷ effort)

**Done in v3.10:** items 1 (pinned resolution), 2 (normalized findings — as `utils/findings.py`, modules still emit dicts), 4 (versioned DB), and the first slice of 7 (`--fail-on`) and 8 (finding history). Still open from this tier: item 3.

**Was: v3.10 — close known gaps**
1. **Pinned target resolution.** `scope.check()` resolves a hostname, then the module resolves it again (DNS-rebinding window). Return the verified IP set and make modules connect to those addresses only.
2. **Findings as a first-class type.** Today findings are free-form dicts. Introduce a `Finding` dataclass (`id`, `severity`, `title`, `evidence`, `remediation`, `refs`, `cwe`, `target`) with `to_dict()` so modules can't drift, and SARIF/risk/diff all key off one stable `id`.
3. **Per-module timeouts and a global scan budget** (wall-clock + packet-rate cap) in the runner rather than in each module.
4. **Schema-versioned local DB** with real migrations (`PRAGMA user_version`) instead of `executescript(_SCHEMA)`.

**Then (v4.0) — platform**
5. **Runner/worker split.** Modules become pure "collectors" returning `Finding`s; one runner owns scope, rate limits, logging, and alerting. Enables parallel multi-target runs and a future agent mode.
6. **Out-of-tree plugins** via entry points (`python_security_toolkit.modules`) with a signature/hash allowlist, so third-party modules don't need to live in `modules/`.
7. **Policy-as-code profiles** (`profiles/cis-lite.yaml`): which modules, which thresholds, which findings fail a build. `scheduled_scan.py --fail-on High` for CI gates.
8. **Trend store**: per-target time series (risk score, MTTR for resolved findings) feeding the dashboard, not just session-vs-previous diffs.

**Vision — where this becomes a product**
9. **Continuous attack-surface monitoring**: scheduled diff of external footprint (subdomains, certs, open ports, headers) with change-only alerts; the pieces (`subdomain_mapper`, `ssl_auditor`, `diff`, `alerting`) already exist.
10. **Evidence-linked remediation**: each finding carries the exact command/config that proves it and a one-click "re-verify" so fixes close findings automatically.
11. **Fleet mode**: small signed agent on hosts (hardening, package CVEs, FIM, Docker, firewall — the local modules) pushing findings to one authenticated collector; the cloud mirror then uses real auth instead of an anon key.
12. **Assisted triage**: optional LLM summarization/prioritization of a session *over the structured findings only* (never raw packets), with an offline mode preserved.

## 4. Guardrails to keep as it grows
- Scope enforcement stays in the runner, never optional per module.
- Anything that ships data off-box is opt-in and documented in `.env.example`.
- New exports must neutralize untrusted strings (HTML-escape, CSV formula prefix, SARIF has no markup).
- Every security fix gets a regression test (see `tests/test_security_fixes.py`).
