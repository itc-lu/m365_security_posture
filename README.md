# M365 Security Posture Management Tool

A fully local, web-based tool for managing and tracking Microsoft 365 security posture across multiple tenants. It combines findings from several assessment tools into one action list per tenant, with a shared "Control Plane" knowledge base for everything that is identical across tenants.

Everything runs on your machine: a Python/Flask web app backed by a single SQLite database. No hosting, no external services.

## Quick Start

```bash
git clone <repository-url>
cd m365_security_posture

pip install -e .            # installs Flask
pip install -e ".[graph]"   # optional: Microsoft Graph API import

m365-posture web            # opens http://localhost:8080
```

Sign in with the default credentials `admin` / `admin` — you are forced to set a new password (minimum 12 characters) on first login.

For production-style use, set a stable session key: `SECRET_KEY=<random> m365-posture web`.

## CLI

The tool is managed entirely through the web UI. The CLI only launches it and migrates old data:

```bash
m365-posture web [-p PORT] [--no-browser] [--db PATH]
m365-posture migrate-from-json [--data-dir DIR] [--db PATH] [--tenant NAME] [--dry-run]
```

`migrate-from-json` imports tenant data from the legacy JSON file layout (`data/<tenant>/actions.json`, …) used by pre-SQLite versions of this tool.

## Data Sources

| Source | Import formats | Notes |
|--------|----------------|-------|
| Microsoft Secure Score | JSON, or directly via Graph API | Graph import also pulls control profiles for rich descriptions |
| SCuBA (CISA ScubaGear) | ZIP of the report directory (recommended), JSON, CSV | ZIP keeps the original HTML report browsable in-app |
| Zero Trust Assessment (report) | ZIP of the report directory (recommended), JSON | ZIP keeps the original HTML report browsable in-app |
| Zero Trust Assessment (legacy) | JSON, CSV | |
| Security Compliance Toolkit | JSON, CSV | |
| M365-Assess | JSON, CSV | |

Graph API import supports four auth methods per tenant: interactive browser (PKCE, no secret), device code, client secret, and certificate (requires `msal`).

PowerShell collection scripts live in `powershell/` (`Collect-SecureScore.ps1`, `Collect-ScubaGear.ps1`, `Collect-ZeroTrust.ps1`).

## How Data Is Organized

### Global vs. per-tenant

Every imported control is split into two layers:

- **Global action** (Control Plane): the tenant-independent knowledge about a control — title, description, workload, priority, risk level, implementation steps, compliance framework mappings, reference URLs. Imports auto-link tenant actions to global actions by source tool + source ID (or title); anything unrecognized is offered for one-click creation or manual linking right after import.
- **Tenant action**: the per-tenant state — status, score, current configuration value, responsible person, planned date, notes, risk acceptance.

**Implementation steps** are global by default but can be overridden per tenant: the action editor offers *Save globally* (updates every tenant) and *Save for this tenant only* (creates an override that can later be reset back to the global value).

### Status handling on re-import

Statuses you set manually (**Completed, In Progress, Risk Accepted**) are never silently overwritten by a report import. When an import disagrees with such a status, the conflict is recorded and shown:

- directly in the import result (per-item *Use imported* / *Keep mine*, plus *…for all* bulk buttons),
- as a banner on the Actions page until every conflict is resolved,
- on the expanded action detail itself.

If a later import agrees with your status again, the conflict clears automatically. Non-protected statuses (e.g. ToDo) simply follow the imported result.

## Web UI Pages

**Tenant pages** (for the active tenant, switchable from the sidebar):

- **Dashboard** – overall and per-tool scores, workload breakdown, trend sparkline, pinned top-priority actions (ROI-ranked), tenant comparison and PDF management report. Scores can exclude *Not Applicable* and *Risk Accepted* actions.
- **Actions** – filterable/sortable action list with expandable detail (description, implementation, notes, linked actions, history), batch status/delete/add-to-plan, cross-tool peer status warnings with one-click sync, and the import-conflict review.
- **Import** – file upload (with per-source hints), Graph API import with all four auth flows, drift summary after each import, stale-action detection, and post-import linking of unrecognized controls to the Control Plane.
- **Plans** – remediation plans with three phases (Quick Wins / Core Controls / Advanced Hardening), auto-phase assignment by ROI, score-gain simulation, licence/effort/user-impact breakdowns and a printable PDF report.
- **Correlations** – actions from different tools grouped by control family (keyword-based auto-correlation); manage the family definitions on the second tab.
- **Essential Eight** – ASD Essential Eight maturity view with radar chart, per-control breakdown and target-level selection.
- **SCuBA** – CISA baseline conformance grouped by product and policy group, with access to the original ScubaGear HTML reports.
- **Compliance** – posture per subscribed framework (NIST 800-53, CIS Microsoft 365, ISO 27001, Essential Eight), rolled up from global-action mappings.
- **Risk Register** – all accepted risks with owner, justification, review/expiry dates; filters for expired / due / unassigned; revoke, extend, CSV export and auto-expiry (expired acceptances revert to ToDo, also enforced on every import).
- **Trending** – score snapshots over time (taken automatically on import, or manually) and drift reports.
- **Export** – GitLab issue export (CSV / JSON / shell script), per-tenant issue templates with `{{variable}}` placeholders, and plan-to-GitLab export.
- **History** – import log and per-action change log.

**Control Plane** (cross-tenant administration):

- **Global Actions** – the shared control library: edit metadata and implementation steps, manage compliance framework mappings, link cross-tool equivalents, see per-tenant instances.
- **Cross-Tenant View** – implementation status of every global action across all tenants side by side.
- **Frameworks** – assign compliance frameworks to tenants (controls which framework views each tenant shows).
- **User Management** – local users with roles (`admin`, `tenant_admin`, `analyst`, `viewer`) and per-tenant / per-workload access restrictions.
- **Tenant Config** – tenant CRUD, Graph API credentials (secret or certificate), framework assignment, user access, and linking of not-yet-globalized actions.
- **Merge / Dedup** – merge duplicate global actions; tenant links, compliance mappings and source aliases follow the surviving record, so future imports keep matching.

## Action Properties

Per action the tool tracks: status (ToDo, In Progress, In Planning, Warning, Risk Accepted, Completed, Not Applicable, Third Party), priority, risk level, user impact, implementation effort, required licence, workload (Entra ID, Exchange Online, SharePoint, OneDrive, Teams, Power Platform, Defender, Intune, Purview, General), score/max score, Essential Eight control + maturity, compliance mappings, dependencies, correlation group, cross-tool links, responsible person, planned date, notes, full change history, and risk-acceptance details.

## Storage

Everything lives in one SQLite database, by default `data/m365_posture.db` (override with `--db` or `--data-dir`). Imported ZT/SCuBA HTML reports are stored next to it under `data/zt_reports/` and `data/scuba_reports/`. Schema creation and migrations run automatically on startup.

## Security Notes

- All API routes require a logged-in session; state-changing requests carry an `X-Requested-With` header as CSRF protection.
- Login is rate-limited (10 attempts / 5 minutes / IP).
- Passwords are stored as PBKDF2-SHA256 hashes; minimum length 12.
- Set `SECRET_KEY` (session signing) and `COOKIE_SECURE=true` (HTTPS deployments) via environment variables.
- Tenant `client_secret` values are never returned by the API (redacted as `***`) and only admins may change them.

## Project Structure

```
m365_posture/
├── cli.py               # CLI: `web` + `migrate-from-json`
├── webapp.py            # Flask REST API
├── web_frontend.py      # Single-page web UI
├── database.py          # SQLite storage layer + schema migrations
├── models.py            # Dataclasses & enums
├── parsers/             # Secure Score, SCuBA, Zero Trust, SCT, M365-Assess
├── graph_api.py         # Microsoft Graph auth flows + fetchers
├── correlation.py       # Cross-tool control-family correlation
├── compliance.py        # Framework auto-mapping
├── planner.py           # ROI scoring, plan simulation, phase suggestion
├── drift.py             # Import-over-import drift detection
├── essential_eight.py   # ASD Essential Eight mapping & maturity
├── scoring.py           # Combined score calculation
├── gitlab_export.py     # GitLab issue export formats
├── storage.py           # Legacy JSON storage (read by migrate-from-json)
└── seed_data/           # E8 mappings, Secure Score control seeds
powershell/              # Collection scripts for the source tools
```

## License

MIT
