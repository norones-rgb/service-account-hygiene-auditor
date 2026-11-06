# Security policy and threat model

## Scope

This is an **assessment-only** tool intended for approved IAM operational review. It reads a JSON snapshot or scoped Active Directory metadata, then writes reports. It deliberately has no password-reset, disable-account, group modification, or remediation execution functionality.

## Trust boundaries

- **Untrusted inputs:** JSON snapshots, AD descriptions/names/SPNs, and configuration paths. Validate before use; never run commands from these fields.
- **Untrusted outputs:** Reports include directory identifiers and access information, even when no secrets are present. Treat them as confidential security evidence.
- **Code output:** CSV protects against formula injection by prefixing cells beginning (possibly after whitespace) with `=`, `+`, `-`, or `@`. HTML encodes all dynamic text and has a restrictive CSP with no scripting. JSON remains plain data.
- **Read access:** The AD mode requires explicit Legacy and Managed search bases, and queries only configured SAM account prefixes for legacy accounts. `privilegedGroups` must be explicitly set before privilege coverage can be Complete.

## Deliberate omissions

- **Not a complete non-human identity inventory:** Prefix-based discovery misses arbitrary user names, accounts outside OUs, app registrations, service principals, local users, scheduled tasks, cloud identities, and non-domain secrets.
- **No secrets collected:** Do not query managed passwords, secret attributes, credentials, Kerberos keys, or hashes.
- **No remediation:** Findings require human review and approval. Especially do not disable accounts solely from `LastLogonDate`.
- **No claim of exhaustive privilege:** Nested-group membership depends on AD query access and domain/forest resolution, and may not cover primary group IDs, cross-forest relationships, or privileged roles assigned outside the configured AD groups.
- **No default assertion of effective control:** A missing attribute or incomplete query is evidence gap, not evidence of safety.
- **No assurance for gMSA/sMSA password age:** Windows/AD manages those passwords, so the legacy password thresholds intentionally exclude them.

## Safe pilot practice

1. Confirm authorization and business objectives. Start with lab/demo data, then a bounded OU.
2. Validate the prefixes, service-account inventory, managed account container, and privileged group identities with domain owners.
3. Use a least-privilege account; avoid domain admin permissions where possible.
4. Store exports in an access-controlled folder, set retention, and use synthetic data for issue reports.
5. Compare a sample of findings with ADUC/approved inventory and ticket evidence; do not disclose customer data publicly.
6. Triage `SA-E*` evidence gaps before a decision that controls are passing.

## Reporting vulnerabilities

Report security issues privately to the repository owner. Do not open public GitHub issues containing real secrets, SIDs, production DNs or customer information.
