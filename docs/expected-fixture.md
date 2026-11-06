# Expected synthetic fixture results

Reference assessment timestamp: **2026-11-05T19:00:00Z**. The fixture contains **11 fabricated accounts** (traditional user-managed service accounts and gMSAs/sMSAs). Expected total **20 findings**:

| Severity | Count |
| --- | ---: |
| Critical | 2 |
| High | 9 |
| Medium | 3 |
| Low | 5 |
| Information | 1 |

| Account | Expected rule IDs |
|---|---|
| `svc_sql_legacy` | SA-001, SA-004, SA-005, SA-007, SA-012 |
| `svc_batch_stale` | SA-005, SA-006, SA-011 |
| `svc_backup_admin` | SA-002, SA-003, SA-007 |
| `svc_web_delegate` | SA-009 |
| `gmsa_web$` | No findings |
| `gmsa_backup$` | SA-007 |
| `svc_retired` | SA-008, SA-011 |
| `svc_expired` | SA-010 |
| `smsa_print$` | No findings |
| `svc_missing_evidence` | SA-E03, SA-011, SA-014 |
| `svc_admin_history` | SA-013 |

`svc_missing_evidence` deliberately contains `null` directory evidence; the overall assessment is therefore **Incomplete evidence - review required**, even though the synthetic snapshot's *declared collection* statuses are both Complete. These are **expected rule results**, not proof that Pester was executed in this environment.
