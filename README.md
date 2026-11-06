# Service Account Hygiene Auditor

> **IAM Automation Toolkit · Project 4/5** | Read-only PowerShell evaluation MVP · Synthetic-first design
>
> [**Portfolio directory**](https://github.com/norones-rgb/ad-ldap-exception-risk-analyzer/blob/main/IAM-AUTOMATION-PORTFOLIO.md) · [**Run the demo**](DEMO.md) · [**Sample HTML preview**](docs/fixture-preview.html) · [**Windows/Linux CI**](https://github.com/norones-rgb/service-account-hygiene-auditor/actions/workflows/ci.yml)
>
> [![Pester CI](https://github.com/norones-rgb/service-account-hygiene-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/norones-rgb/service-account-hygiene-auditor/actions/workflows/ci.yml) · PowerShell 7.2+ · CSV / JSON / offline HTML output


**Read-only PowerShell IAM security analysis | ISGIN portfolio MVP v0.1**

Review traditional user-based Active Directory service accounts and managed service accounts (gMSAs/sMSAs) for risky delegation settings, preauthentication gaps, old user-managed passwords, privileges, approximate inactivity, governance ownership, and incomplete evidence. Export review-ready **HTML, CSV, and JSON** without modifying directory objects.

> **Status:** v0.1 is a review prototype, not a certification of compliance or a substitute for your organization's IAM/security control process. Validate all findings with owners. Incomplete inventory or group evidence never counts as a clean result.

## Highlights

- Three modes: **Demo** (fabricated snapshot), **Snapshot** (offline JSON), and **AD** (scoped, read-only retrieval).
- Explicit distinction between **UserService**, **gMSA**, and **sMSA**; password-age/never-expires checks apply **only** to enabled user-managed service accounts.
- **14 security/governance checks**, plus **3 evidence-gap checks**; configurable 180-day password, 365-day SPN/password, and 90-day inactivity thresholds.
- Supports checking configured privileged groups **including nested membership**. Group queries that fail produce `Partial` evidence instead of false assurances.
- Pester 5 tests and CI matrix for Windows and Ubuntu (PowerShell 7.2+).
- All sample identities and service names are fictional; no secrets, credentials, production tenant IDs or private company information.

## Quickstart: offline demo

Requirements: **PowerShell 7.2+**. Demo and Snapshot modes do not require RSAT, a domain, credentials, or network access.

```powershell
# From the repository root
pwsh -NoProfile -File ./Invoke-ServiceAccountHygieneAudit.ps1 `
  -Mode Demo -AsOfUtc '2026-11-05T19:00:00Z'
```

Open the generated `output/service-account-audit-<timestamp>-<id>.html` in your browser. The same unique run basename has `.csv` and `.json` companions. On Linux/macOS, you may call `./Invoke-ServiceAccountHygieneAudit.ps1` from within a PowerShell session, or use `pwsh -File`.

**Synthetic expected results at the pinned assessment time:** 11 accounts; **20 findings** (2 critical, 9 high, 3 medium, 5 low, 1 informational evidence gap). See [Expected fixture](docs/expected-fixture.md) or [static preview](docs/fixture-preview.html). The preview is generated independently of PowerShell and does **not** demonstrate a passing Pester run.

## Analyze your own read-only snapshot

```powershell
pwsh -NoProfile -File ./Invoke-ServiceAccountHygieneAudit.ps1 `
  -Mode Snapshot -SnapshotPath ./sample-data/service-accounts.synthetic.json `
  -ConfigPath ./config/default.json `
  -OutputDirectory ./output `
  -AsOfUtc '2026-11-05T19:00:00Z'
```

Review [schema and mapping](docs/snapshot-schema.md). JSON fields are explicit nullable booleans and UTC ISO-8601 timestamps. Do **not** put real account snapshots in Git. The `output/` folder is ignored; store private input snapshots outside the checkout.

## Collect Active Directory evidence (read-only)

Requirements: **Windows**, PowerShell 7.2+ with the **ActiveDirectory** module available (e.g., RSAT), suitable AD read permissions, and approved scope.

**Before you run:** copy `config/default.json` into a local configuration file and add the actual group identities for your domain. The default `privilegedGroups` list is deliberately empty; without explicitly configured groups, the report identifies privilege evidence as **NotCollected**. Configure only groups you are authorized to audit.

```powershell
# Example ONLY; replace these fictional paths and group names
# Copy config/default.json to config/local.example.json and edit the latter.
pwsh -NoProfile -File ./Invoke-ServiceAccountHygieneAudit.ps1 `
  -Mode AD `
  -LegacySearchBase 'OU=Service Accounts,DC=example,DC=test' `
  -ManagedSearchBase 'CN=Managed Service Accounts,DC=example,DC=test' `
  -ConfigPath './config/local.example.json' `
  -OutputDirectory './output' `
  -Server 'dc01.example.test'
```

`-Server` is optional; specifying an exact domain controller is useful for repeatability. Two separate search bases are mandatory so traditional and managed account collections cannot silently expand to the whole directory. The legacy account discovery criteria are the SAM account prefixes in configuration (`svc_`, `svc-`, `sa_` by default); **this is not a complete inventory** of all service accounts. Managed accounts are discovered via `Get-ADServiceAccount` inside the declared managed search base.

The collector queries `Get-ADUser`, `Get-ADServiceAccount`, and optionally `Get-ADGroupMember -Recursive`. It does **not** run `Set-AD*`, disable accounts, change passwords, alter SPNs, test logons, or retrieve managed account passwords. A terminating account-query error stops the run rather than producing a misleading result. Failed privileged group queries are reported as `Partial`.

The `owner` field in AD mode is sourced from `managedBy` when present. A `managedBy` entry is a directory owner reference, **not verified business ownership**. Reconcile it against the approved service inventory.

## Risk rules

| Rule | Severity | Observation (enabled unless stated) |
| --- | --- | --- |
| SA-001 | Critical | Unconstrained delegation flag |
| SA-002 | Critical | Kerberos preauthentication not required |
| SA-003 | High | DES-only key flag |
| SA-004 | High | User-managed service account password never expires |
| SA-005 | High | User-managed account password age over configured threshold |
| SA-006 | Medium | Approximate, replicated last-logon date is stale |
| SA-007 | High | Privileged membership observed in selected groups |
| SA-008 | Medium | **Disabled** account remains in a selected privileged group |
| SA-009 | Medium | Constrained delegation / protocol transition for review |
| SA-010 | High | Enabled account past its expiration date |
| SA-011 | Low | No owner recorded in snapshot |
| SA-012 | High | SPN + old password for user-managed service account |
| SA-013 | Low | `adminCount=1` (historical indicator, not proof of privilege) |
| SA-014 | Low | Older enabled account has no replicated logon date |
| SA-E01/E02/E03 | Information | Incomplete accounts, group coverage, or key attribute evidence |

Thresholds are **review criteria**, not automatic statements that an account is misconfigured or compromised. See [rules and limits](docs/rules.md) and [security guidance](SECURITY.md).

## Project layout

```text
service-account-hygiene-auditor/
├── Invoke-ServiceAccountHygieneAudit.ps1
├── src/ServiceAccountHygiene.psm1
├── config/default.json
├── sample-data/service-accounts.synthetic.json
├── tests/ServiceAccountHygiene.Tests.ps1
├── docs/
│   ├── architecture.md
│   ├── rules.md
│   ├── expected-fixture.md
│   ├── snapshot-schema.md
│   ├── pilot-checklist.md
│   └── fixture-preview.html
├── .github/workflows/ci.yml
├── SECURITY.md
├── NOTICE
├── .gitignore
└── output/.gitkeep
```

## Run automated tests

```powershell
Install-Module Pester -MinimumVersion 5.6.1 -Scope CurrentUser -Force
Import-Module Pester -MinimumVersion 5.6.1
Invoke-Pester -Path ./tests -Output Detailed
```

**Environment note:** These Pester tests have not been executed in the ChatGPT build environment, which has no `pwsh` executable. The fixture, file layouts, JSON, and preview can be validated independently; PowerShell test execution must happen locally or with CI after publishing. Review any CI failures before a pilot.

## Handling sensitive outputs

- Do not commit customer data, real account exports, SID/group membership graphs, SPNs, passwords, hashes, or internal DNs to a public repository.
- `output/` and `config/local.*.json` are ignored. **Input JSON paths elsewhere are not automatically protected by `.gitignore`**; keep them outside the repository.
- Use least-privilege read access, documented authorization, approved retention, and controlled storage locations.
- Do not use this tool to make automated access removal decisions. A last-logon date is approximate and must be corroborated.

## Further reading

- [Microsoft Learn: Get-ADServiceAccount](https://learn.microsoft.com/powershell/module/activedirectory/get-adserviceaccount)
- [Microsoft Learn: Get-ADGroupMember](https://learn.microsoft.com/powershell/module/activedirectory/get-adgroupmember)
- [Microsoft Learn: Secure standalone managed service accounts](https://learn.microsoft.com/entra/identity-platform/secure-standalone-managed-service-accounts) (see also official Entra security guidance)
- [Microsoft AD DS blog: lastLogonTimestamp behavior](https://techcommunity.microsoft.com/blog/askds/the-lastlogontimestamp-attribute---what-it-was-designed-for-and-how-it-works/396204)

## License and commercialization

No open-source license is granted in this prototype. See `NOTICE`. The public demonstration contains only general inspection logic and synthetic data; future proprietary ISGIN components should be separately designed and licensed after review.