# Read-only AD pilot checklist

- [ ] Receive written approval to review service identities, groups, and outputs in designated OU/container scope.
- [ ] Validate AD PowerShell module support on the chosen Windows host (`Get-Module -ListAvailable ActiveDirectory`).
- [ ] Run demo and verify the baseline 20 findings; run `Invoke-Pester` before connecting live directory data.
- [ ] List legacy SAM naming conventions, plus exceptions (prefix-based coverage is intentionally incomplete).
- [ ] Confirm actual container(s) for gMSAs and sMSAs. Select two explicit search bases.
- [ ] Map privileged groups using domain-qualified/SID identities where ambiguous; understand nesting and cross-domain limitations.
- [ ] Save modified config as `config/local.<environment>.json` (excluded from Git).
- [ ] Use least-privileged AD read rights and secure report storage with approved access and retention.
- [ ] Run a bounded pilot with `-Mode AD -LegacySearchBase ... -ManagedSearchBase ...` and no remedial changes.
- [ ] Triage `SA-E01`/`SA-E02`/`SA-E03` evidence gaps before any clean-control assertion.
- [ ] Spot-check at least one case from each raised rule in AD and the approved service owner inventory.
- [ ] Confirm `LastLogonDate` against domain authentication activity, service owner knowledge and maintenance windows.
- [ ] Get explicit approvals and ticket numbers before separately remediating any finding.
- [ ] Share only synthetic/redacted data when filing public GitHub issues.
