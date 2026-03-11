# M365 Security Posture Management Tool

A fully local CLI tool for managing and tracking Microsoft 365 security posture across multiple tenants. Combines data from multiple security assessment sources into a unified dashboard with historical tracking, Essential Eight mapping, and GitLab issue export.

## Features

- **Multi-tenant management** - Add, switch, and compare security posture across tenants
- **Multiple data sources** - Microsoft Secure Score, SCuBA (CISA), Zero Trust Assessment, Security Compliance Toolkit, M365-Assess
- **Workload differentiation** - Entra ID, Exchange Online, SharePoint, OneDrive, Teams, Power Platform, Defender, Intune, Purview
- **Essential Eight mapping** - Automatic mapping to ASD's Essential Eight controls with maturity level assessment
- **Combined scoring** - Unified score across all tools while preserving individual tool scores
- **Historical tracking** - Track changes over time; re-importing reports updates status without voiding history
- **Action management** - Tag actions (Risk Accepted, In Planning, Completed, etc.), set priority, risk, effort, responsible person, planned date
- **HTML dashboards** - Rich interactive reports with gauges, filters, sorting, and detail panels
- **Tenant comparison** - Side-by-side comparison of security posture between tenants
- **GitLab export** - CSV, JSON, and shell script formats for bulk issue creation
- **MS Graph integration** - Auto-fetch Secure Score via app registration or interactive auth
- **PowerShell collectors** - Scripts for ScubaGear, Zero Trust Assessment, and Secure Score collection
- **Fully local** - No hosting, no external services. JSON file storage, Python CLI

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd m365_security_posture

# Install (no external dependencies required for core features)
pip install -e .

# Optional: Install MS Graph API support
pip install -e ".[graph]"
```

## Quick Start

```bash
# 1. Add a tenant
m365-posture tenant add contoso --tenant-id "YOUR-TENANT-ID" --display-name "Contoso Ltd"

# 2. Import assessment data
m365-posture import scuba ./ScubaResults.json
m365-posture import secure-score ./secure_score.json
m365-posture import zero-trust ./zt_assessment.json
m365-posture import sct ./baseline_results.csv
m365-posture import m365-assess ./m365assess_output.json

# 3. View scores
m365-posture score

# 4. View Essential Eight compliance
m365-posture e8

# 5. Generate HTML dashboard
m365-posture report -o dashboard.html

# 6. Compare tenants
m365-posture compare "contoso,fabrikam" --report comparison.html
```

## CLI Commands

### Tenant Management

```bash
m365-posture tenant add <name> [--tenant-id ID] [--display-name NAME] [--client-id ID] [--client-secret SECRET] [--interactive]
m365-posture tenant list
m365-posture tenant switch <name>
m365-posture tenant remove <name> [-y]
```

### Import Data

```bash
m365-posture import <source> <file>
# Sources: secure-score, scuba, zero-trust, sct, m365-assess
# Formats: JSON, CSV
```

### Fetch from MS Graph

```bash
# Auto-fetch Secure Score (requires auth configuration)
m365-posture fetch secure-score
```

### View & Manage Actions

```bash
m365-posture actions list [--status STATUS] [--workload WORKLOAD] [--source SOURCE] [--priority PRIORITY]
m365-posture actions show <id>
m365-posture actions update <id> --status "In Planning" --responsible "Jane" --planned-date "2026-04-01" --by "admin"
```

### Scoring & Reports

```bash
m365-posture score                                      # Show combined scores
m365-posture e8                                         # Essential Eight summary
m365-posture report [-o output.html]                    # HTML dashboard
m365-posture compare "tenant1,tenant2" [--report out.html]  # Compare tenants
m365-posture history                                    # Import history
```

### GitLab Export

```bash
m365-posture export --format csv -o gitlab_issues.csv
m365-posture export --format json -o gitlab_issues.json [--project-id 123]
m365-posture export --format script -o create_issues.sh [--project-path GROUP/PROJECT]
m365-posture export --status "ToDo,In Planning"         # Filter by status
```

## Data Sources

| Source | Import Format | Auto-Fetch | Description |
|--------|--------------|------------|-------------|
| Microsoft Secure Score | JSON | Yes (Graph API) | Microsoft's built-in security scoring |
| SCuBA (CISA ScubaGear) | JSON, CSV | No | CISA's M365 security baseline assessment |
| Zero Trust Assessment | JSON, CSV | No | Zero Trust maturity assessment |
| Security Compliance Toolkit | JSON, CSV | No | Microsoft GPO/baseline comparison |
| M365-Assess | JSON, CSV | No | Community M365 assessment tool |

## PowerShell Collection Scripts

PowerShell scripts in `powershell/` automate data collection:

```powershell
# Collect Secure Score
.\powershell\Collect-SecureScore.ps1 -TenantId "xxx" -ClientId "yyy" -ClientSecret "zzz"

# Run ScubaGear assessment
.\powershell\Collect-ScubaGear.ps1 -TenantId "xxx" -Products "aad,exo,teams"

# Run Zero Trust Assessment
.\powershell\Collect-ZeroTrust.ps1 -TenantId "xxx"
```

## Essential Eight Mapping

Actions are automatically mapped to ASD's Essential Eight controls:
- Application Control
- Patch Applications
- Configure Microsoft Office Macro Settings
- User Application Hardening
- Restrict Administrative Privileges
- Patch Operating Systems
- Multi-Factor Authentication
- Regular Backups

Maturity levels (0-3) are estimated based on action details. Reference: [ASD Blueprint](https://blueprint.asd.gov.au/security-and-governance/essential-eight/)

## Action Properties

Each action tracks:
- **ID** - Unique identifier
- **Status** - ToDo, In Progress, In Planning, Risk Accepted, Completed, Not Applicable, Third Party
- **Priority** - Critical, High, Medium, Low, Informational
- **Risk Level** - Critical, High, Medium, Low, Minimal
- **User Impact** - High, Medium, Low, None
- **Implementation Effort** - High, Medium, Low, Minimal
- **Required Licence** - Azure AD P1, E5, etc.
- **Workload** - Entra ID, Exchange Online, SharePoint, Teams, etc.
- **Essential Eight** - Control and maturity level mapping
- **Planned Date** and **Responsible** person
- **History** - Full change tracking with timestamps

## Project Structure

```
m365_security_posture/
├── m365_posture/
│   ├── __init__.py          # Package init
│   ├── __main__.py          # Entry point
│   ├── cli.py               # CLI interface
│   ├── models.py            # Data models
│   ├── storage.py           # JSON storage layer
│   ├── scoring.py           # Scoring engine
│   ├── essential_eight.py   # E8 mapping
│   ├── report.py            # HTML report generator
│   ├── gitlab_export.py     # GitLab issue export
│   ├── collectors/
│   │   └── graph_client.py  # MS Graph API client
│   └── parsers/
│       ├── secure_score.py  # Secure Score parser
│       ├── scuba.py         # SCuBA parser
│       ├── zero_trust.py    # Zero Trust parser
│       ├── sct.py           # SCT parser
│       └── m365_assess.py   # M365-Assess parser
├── powershell/
│   ├── Collect-SecureScore.ps1
│   ├── Collect-ScubaGear.ps1
│   └── Collect-ZeroTrust.ps1
├── data/                    # Tenant data (JSON files)
├── pyproject.toml
├── requirements.txt
└── README.md
```

## Storage

All data is stored as JSON files under `data/<tenant-name>/`:
- `config.json` - Tenant configuration
- `actions.json` - All security actions
- `scores.json` - Aggregated scores per tool
- `import_history.json` - Import audit trail
- `reports/` - Generated reports and fetched data

## License

MIT
