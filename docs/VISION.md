# Vision & Mission

## Mission

Give security teams and service providers **one place to manage the Microsoft 365
security posture of every tenant they are responsible for** — turning the scattered
output of assessment tools into a single, prioritized, tracked remediation program.

## Vision

The definitive **local-first, multi-tenant M365 posture cockpit**:

1. **Aggregate, don't re-measure.** Authoritative tools (Microsoft Secure Score, CISA
   ScubaGear, Zero Trust Assessment, SCT, M365-Assess, …) do the measuring; we parse,
   normalize, deduplicate and correlate their findings into one action list per tenant.
2. **Shared knowledge, per-tenant state.** Everything that is true for every tenant
   (control descriptions, implementation steps, framework mappings) lives once in the
   Control Plane; everything tenant-specific (status, owner, dates, risk decisions)
   lives on the tenant action.
3. **Workflow, not just scoring.** Statuses that survive re-imports, dependencies,
   remediation plans with ROI phasing, risk acceptance with expiry and audit — posture
   management is change management.
4. **Every framework at once.** One fix should count everywhere it applies: Secure
   Score, SCuBA baselines, CIS, NIST 800-53, ISO 27001, Essential Eight maturity.
5. **Fully local.** A Python web app and a SQLite file. No hosting, no SaaS, no
   customer data leaving the machine. Anything that must run remotely (the assessment
   tools) is driven explicitly and its output imported.
6. **Evidence for management.** Trends, drift, comparisons and printable reports that
   a non-technical stakeholder can read.

## Guiding principles

- **Local-first**: bind to localhost by default; secrets stay on disk with restrictive
  permissions; no telemetry.
- **Import is never destructive**: user decisions (Completed, Risk Accepted, In
  Progress) are protected; conflicts are surfaced, not silently resolved.
- **Wrong-tenant safety**: reports carrying a tenant identity are verified against the
  import target.
- **Least privilege in-app**: roles (admin / tenant_admin / analyst / viewer), per-tenant
  and per-workload access, admin-only credential and automation-config management,
  audit logging for security-relevant operations.
- **Standard library over dependencies**: Flask is the only required dependency.

## Alignment assessment (2026-08)

| Vision element | Status | Notes |
|---|---|---|
| Multi-tenant aggregation of 5+ sources | ✅ | Secure Score, SCuBA, ZT (2 formats), SCT, M365-Assess |
| Control Plane shared knowledge base | ✅ | Global actions, merge/dedupe, aliases, overrides |
| Protected statuses & conflict workflow | ✅ | Per-item and bulk resolution |
| Multi-framework rollups | ✅ | NIST, CIS, ISO, Essential Eight, SCuBA |
| Fully local | ✅ | Default bind is now 127.0.0.1 (`--host` to override) |
| Automation without leaving the machine | ✅ | Built-in scheduler drives ScubaGear/ZT/Graph |
| Management evidence | ✅ | PDF reports, Excel everywhere, trends, drift |
| Notifications on regression | ❌ | Roadmap R2 (see GAP analysis) |
| Maester as an additional source | ❌ | Roadmap R1/R3 (see GAP analysis) |
| Headless CI mode | ❌ | Roadmap R4 |
| National cloud endpoints | ❌ | Roadmap R6 |

The full competitive analysis and roadmap live in
[GAP_ANALYSIS_MAESTER.md](GAP_ANALYSIS_MAESTER.md).
