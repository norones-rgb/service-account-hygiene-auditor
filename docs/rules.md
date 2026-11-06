# Rule catalog and interpretation

All findings are **candidates for review**, not confirmation of compromise. This MVP uses generic thresholds that must be adjusted to organizational standards.

| Rule | Scope | Observation | Important qualification |
|---|---|---|---|
| SA-001 | Enabled any type | `trustedForDelegation=true` | Unconstrained delegation is high-risk; validate alternate designs before change |
| SA-002 | Enabled any type | `doesNotRequirePreAuth=true` | Review AS-REP preauthentication exposure |
| SA-003 | Enabled any type | `useDESKeyOnly=true` | Flags a legacy encryption setting, not a complete cryptographic audit |
| SA-004 | Enabled `UserService` | `passwordNeverExpires=true` | Exceptions sometimes exist; gMSA/sMSA deliberately excluded |
| SA-005 | Enabled `UserService` | PasswordLastSet age >= `passwordAgeDays` | Missing dates reported as evidence gaps; not a password-policy enforcement engine |
| SA-006 | Enabled any type | LastLogonDate age >= `inactivityDays` | Replicated approximate `lastLogonTimestamp`; corroborate before changing access |
| SA-007 | Enabled any type | Present in one or more configured privileged groups | Positive observed group membership only; some privileges are legitimate |
| SA-008 | **Disabled** any type | Present in configured privileged group(s) | Disabled account may still retain historical entitlements; remove per change process |
| SA-009 | Enabled any type | Delegation targets or `trustedToAuthForDelegation` | Constrained delegation may be legitimate; review target restrictions |
| SA-010 | Enabled any type | AccountExpirationDate <= assessment date | Check account lifecycle and attribute interpretation |
| SA-011 | Any type | Snapshot owner blank | `managedBy` metadata is not necessarily business ownership |
| SA-012 | Enabled `UserService` | SPN + password age >= `spnPasswordAgeDays` | Review exposure and rotation; does not test password strength |
| SA-013 | Enabled any type | `adminCount=1` with no selected privilege observation | Can be historical/stale; not proof of current privilege |
| SA-014 | Enabled any type | No lastLogonDate although created >= inactivity threshold | Absence of replicated value is not evidence of no sign-ins |
| SA-E01 | Collection | Account scan incomplete | No passing conclusion can be drawn |
| SA-E02 | Collection | Privilege scan incomplete or not collected | Negative membership observations cannot be trusted |
| SA-E03 | Account | Security flags or legacy password date missing | Missing fields do not mean false |

### Risk and evidence logic

- Severities are a triage rubric; each organization should approve one. The rule engine does **not** automatically disable accounts or send notifications.
- Critical/high observations may coexist for one account, e.g. user service account with a stale password and SPN. Multiple findings are intentional.
- If the source reports `Complete` for configured group collection, the tool trusts that declaration. A malicious or inaccurate snapshot can mislead the tool; verify source provenance.
- gMSA and sMSA passwords are domain-managed. User-managed password rules SA-004, SA-005, and SA-012 intentionally do not apply to these account types.
- `LastLogonDate` is derived from replicated `lastLogonTimestamp`, which is updated with delay and might be absent. Never treat this as evidence of precise session activity.
