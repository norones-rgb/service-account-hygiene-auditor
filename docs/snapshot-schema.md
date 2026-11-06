# Snapshot schema v1

The analyzer accepts a JSON object (example in `sample-data/service-accounts.synthetic.json`):

```json
{
  "schemaVersion": 1,
  "generatedUtc": "2026-11-05T19:00:00Z",
  "source": "synthetic-fixture",
  "collection": {
    "accountsStatus": "Complete",
    "privilegedMembershipStatus": "Complete",
    "queriedPrivilegedGroups": ["Domain Admins"],
    "warnings": []
  },
  "accounts": [
    {
      "sid": "S-1-5-21-12345-23456-34567-1100",
      "samAccountName": "svc_example",
      "accountType": "UserService",
      "enabled": true,
      "owner": "Platform Team",
      "createdUtc": "2025-05-01T00:00:00Z",
      "lastLogonUtc": "2026-10-01T00:00:00Z",
      "passwordLastSetUtc": "2026-07-01T00:00:00Z",
      "accountExpiresUtc": null,
      "passwordNeverExpires": false,
      "doesNotRequirePreAuth": false,
      "trustedForDelegation": false,
      "trustedToAuthForDelegation": false,
      "useDESKeyOnly": false,
      "adminCount": 0,
      "servicePrincipalNames": [],
      "delegationTargets": [],
      "privilegedGroups": []
    }
  ]
}
```

## Required rules

- `schemaVersion` exactly `1`; all SIDs unique and all account names nonempty.
- `accountType` one of `UserService`, `gMSA`, or `sMSA`; case-sensitive.
- Boolean flags must be literal JSON booleans (`true`, `false`) or null. The analyzer rejects string booleans (`"false"`), which have dangerous PowerShell truthiness.
- Date fields are ISO 8601 with `Z` or `±HH:MM` offsets or null; naive local timestamps are rejected. `-AsOfUtc` also needs an explicit offset.
- `servicePrincipalNames`, `delegationTargets`, and `privilegedGroups` must be arrays of nonempty strings (empty arrays allowed; **missing/null arrays are rejected** to avoid false-negative evidence).
- `collection.accountsStatus` and `collection.privilegedMembershipStatus`: `Complete`, `Partial`, `NotCollected`.
- The snapshot must contain at least one account. An empty collection is not allowed to produce a potentially misleading zero-finding report.
- `owner` is a string or null; `adminCount` integer or null.
- Null directory evidence never turns into a false/negative assertion.

## AD attribute mapping

| Snapshot field | Live AD property / interpretation |
|---|---|
| `sid` | `.SID.Value` |
| `accountType` | `Get-ADUser` => UserService; managed ObjectClass => gMSA or sMSA |
| `owner` | `managedBy` DN when available (not verified business owner) |
| `createdUtc` | `whenCreated` |
| `lastLogonUtc` | `LastLogonDate` (replicated approximation) |
| `passwordLastSetUtc` | `PasswordLastSet` |
| `accountExpiresUtc` | `AccountExpirationDate` |
| delegation, preauth, DES flags | Same-named extended AD properties |
| `servicePrincipalNames` | `ServicePrincipalNames` |
| `delegationTargets` | `msDS-AllowedToDelegateTo` |
| `privilegedGroups` | Account SID intersected with `Get-ADGroupMember -Recursive` results for configured groups |

Some managed-account attribute values may be unavailable depending on directory schema, permissions, and AD module behavior. Such missing values surface as evidence gaps when relevant to the engine's critical flags.
