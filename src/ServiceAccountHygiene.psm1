#Requires -Version 7.2
Set-StrictMode -Version Latest

function Get-RecordValue {
    param([Parameter(Mandatory)][object]$Record, [Parameter(Mandatory)][string]$Key)
    if ($Record -is [System.Collections.IDictionary]) {
        if ($Record.Contains($Key)) { return ,($Record[$Key]) }
        return $null
    }
    $property = $Record.PSObject.Properties[$Key]
    if ($null -eq $property) { return $null }
    return ,($property.Value)
}

function Test-RecordKey {
    param([Parameter(Mandatory)][object]$Record, [Parameter(Mandatory)][string]$Key)
    if ($Record -is [System.Collections.IDictionary]) { return $Record.Contains($Key) }
    return $null -ne $Record.PSObject.Properties[$Key]
}

function ConvertTo-UtcInstant {
    param([AllowNull()][object]$Value, [string]$Field = 'timestamp')
    if ($null -eq $Value -or ([string]$Value).Trim() -eq '') { return $null }
    if ($Value -is [datetimeoffset]) { return $Value.ToUniversalTime() }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { throw "Field '$Field' requires an explicit timezone." }
        return ([datetimeoffset]$Value).ToUniversalTime()
    }
    $valueText = [string]$Value
    if ($valueText -notmatch '(Z|[+\-]\d{2}:\d{2})$') {
        throw "Field '$Field' requires an ISO 8601 timestamp with UTC offset."
    }
    $parsed = [datetimeoffset]::MinValue
    if (-not [datetimeoffset]::TryParse($valueText, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$parsed)) {
        throw "Field '$Field' contains an invalid timestamp."
    }
    return $parsed.ToUniversalTime()
}

function Assert-BooleanOrNull {
    param([object]$Value, [string]$Field)
    if ($null -ne $Value -and $Value -isnot [bool]) { throw "Field '$Field' must be true, false, or null." }
}

function Get-StringArray {
    param([AllowNull()][object]$Value, [string]$Field)
    if ($null -eq $Value) { throw "Field '$Field' must be an array; use [] to represent a confirmed empty list." }
    if ($Value -is [string] -or $Value -isnot [array]) { throw "Field '$Field' must be an array of strings." }
    $result = [Collections.Generic.List[string]]::new()
    foreach ($item in $Value) {
        if ($item -isnot [string] -or [string]::IsNullOrWhiteSpace($item)) { throw "Field '$Field' must contain nonempty strings only." }
        $result.Add([string]$item)
    }
    return ,($result.ToArray())
}

function Assert-Configuration {
    param([Parameter(Mandatory)][object]$Configuration)
    $days = Get-RecordValue $Configuration 'passwordAgeDays'
    $inactivity = Get-RecordValue $Configuration 'inactivityDays'
    $spn = Get-RecordValue $Configuration 'spnPasswordAgeDays'
    foreach ($entry in @(@('passwordAgeDays', $days), @('inactivityDays', $inactivity), @('spnPasswordAgeDays', $spn))) {
        $value = $entry[1]
        if ($null -eq $value -or ($value -isnot [int] -and $value -isnot [long]) -or $value -lt 1 -or $value -gt 3650) {
            throw "Configuration '$($entry[0])' must be an integer between 1 and 3650."
        }
    }
    if ([int]$spn -le [int]$days) { throw 'spnPasswordAgeDays must be greater than passwordAgeDays.' }
    $prefixes = Get-StringArray (Get-RecordValue $Configuration 'legacySamPrefixes') 'legacySamPrefixes'
    foreach ($prefix in $prefixes) {
        if ($prefix -notmatch '^[a-zA-Z0-9_-]{2,20}$') { throw 'legacySamPrefixes may only include letters, digits, underscores and hyphens (2-20 chars).' }
    }
    $null = Get-StringArray (Get-RecordValue $Configuration 'privilegedGroups') 'privilegedGroups'
}

function Assert-Snapshot {
    param([Parameter(Mandatory)][object]$Snapshot)
    if ((Get-RecordValue $Snapshot 'schemaVersion') -ne 1) { throw 'Unsupported snapshot schemaVersion (expected 1).' }
    if ($null -eq (ConvertTo-UtcInstant (Get-RecordValue $Snapshot 'generatedUtc') 'generatedUtc')) { throw 'Snapshot generatedUtc is required.' }
    $collection = Get-RecordValue $Snapshot 'collection'
    if ($null -eq $collection) { throw 'Snapshot collection metadata is required.' }
    foreach ($field in @('accountsStatus','privilegedMembershipStatus')) {
        $status = Get-RecordValue $collection $field
        if ($status -cnotin @('Complete','Partial','NotCollected')) { throw "Invalid collection status '$field'." }
    }
    $accounts = Get-RecordValue $Snapshot 'accounts'
    if ($null -eq $accounts -or $accounts -isnot [array] -or $accounts.Count -eq 0) {
        throw 'Snapshot must contain at least one account. Refusing an empty, potentially false-clean scan.'
    }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($account in $accounts) {
        $sid = [string](Get-RecordValue $account 'sid')
        $sam = [string](Get-RecordValue $account 'samAccountName')
        $kind = [string](Get-RecordValue $account 'accountType')
        if ([string]::IsNullOrWhiteSpace($sid) -or [string]::IsNullOrWhiteSpace($sam)) { throw 'Every account requires nonempty sid and samAccountName.' }
        if ($kind -cnotin @('UserService','gMSA','sMSA')) { throw "Unknown accountType for '$sam'." }
        if (-not $seen.Add($sid)) { throw "Duplicate account SID in snapshot: '$sid'." }
        foreach ($field in @('enabled','passwordNeverExpires','doesNotRequirePreAuth','trustedForDelegation','useDESKeyOnly','trustedToAuthForDelegation')) {
            Assert-BooleanOrNull (Get-RecordValue $account $field) "$sam.$field"
        }
        foreach ($field in @('passwordLastSetUtc','lastLogonUtc','createdUtc','accountExpiresUtc')) {
            $null = ConvertTo-UtcInstant (Get-RecordValue $account $field) "$sam.$field"
        }
        foreach ($field in @('servicePrincipalNames','delegationTargets','privilegedGroups')) {
            $null = Get-StringArray (Get-RecordValue $account $field) "$sam.$field"
        }
        $adminCount = Get-RecordValue $account 'adminCount'
        if ($null -ne $adminCount -and ($adminCount -isnot [int] -and $adminCount -isnot [long])) { throw "Field '$sam.adminCount' must be an integer or null." }
    }
}

function Add-AuditFinding {
    param(
        [Parameter(Mandatory)][Collections.Generic.List[object]]$List,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Severity,
        [Parameter(Mandatory)][object]$Account,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Evidence,
        [Parameter(Mandatory)][string]$Action,
        [string]$Confidence = 'Observed'
    )
    $List.Add([pscustomobject][ordered]@{
        RuleId = $Id
        Severity = $Severity
        Account = [string](Get-RecordValue $Account 'samAccountName')
        AccountSid = [string](Get-RecordValue $Account 'sid')
        AccountType = [string](Get-RecordValue $Account 'accountType')
        Title = $Title
        Evidence = $Evidence
        RecommendedAction = $Action
        Confidence = $Confidence
    })
}

function Invoke-ServiceAccountHygieneAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Snapshot,
        [Parameter(Mandatory)][object]$Configuration,
        [Parameter(Mandatory)][string]$AsOfUtc
    )
    Assert-Configuration $Configuration
    Assert-Snapshot $Snapshot
    $now = ConvertTo-UtcInstant $AsOfUtc 'AsOfUtc'
    if ($null -eq $now) { throw 'AsOfUtc is mandatory.' }
    $findings = [Collections.Generic.List[object]]::new()
    $accounts = Get-RecordValue $Snapshot 'accounts'
    $collection = Get-RecordValue $Snapshot 'collection'
    $accountStatus = [string](Get-RecordValue $collection 'accountsStatus')
    $groupStatus = [string](Get-RecordValue $collection 'privilegedMembershipStatus')
    $collectionAccount = @{samAccountName='[collection]';sid='[collection]';accountType='Collection'}
    if ($accountStatus -ne 'Complete') {
        Add-AuditFinding $findings 'SA-E01' 'Information' $collectionAccount 'Account collection incomplete' "Account collection status: $accountStatus." 'Resolve collector errors and rerun before concluding that accounts are risk-free.' 'Unknown'
    }
    if ($groupStatus -ne 'Complete') {
        Add-AuditFinding $findings 'SA-E02' 'Information' $collectionAccount 'Privileged membership evidence incomplete' "Group collection status: $groupStatus." 'Configure and successfully query the intended privileged groups; do not interpret missing membership as evidence of no access.' 'Unknown'
    }
    foreach ($account in $accounts) {
        $name = [string](Get-RecordValue $account 'samAccountName')
        $kind = [string](Get-RecordValue $account 'accountType')
        $enabled = Get-RecordValue $account 'enabled'
        $groups = Get-StringArray (Get-RecordValue $account 'privilegedGroups') "$name.privilegedGroups"
        $spns = Get-StringArray (Get-RecordValue $account 'servicePrincipalNames') "$name.servicePrincipalNames"
        $targets = Get-StringArray (Get-RecordValue $account 'delegationTargets') "$name.delegationTargets"
        $lastLogon = ConvertTo-UtcInstant (Get-RecordValue $account 'lastLogonUtc') "$name.lastLogonUtc"
        $passwordLastSet = ConvertTo-UtcInstant (Get-RecordValue $account 'passwordLastSetUtc') "$name.passwordLastSetUtc"
        $created = ConvertTo-UtcInstant (Get-RecordValue $account 'createdUtc') "$name.createdUtc"
        $expires = ConvertTo-UtcInstant (Get-RecordValue $account 'accountExpiresUtc') "$name.accountExpiresUtc"
        $passwordNeverExpires = Get-RecordValue $account 'passwordNeverExpires'
        $preAuth = Get-RecordValue $account 'doesNotRequirePreAuth'
        $delegation = Get-RecordValue $account 'trustedForDelegation'
        $des = Get-RecordValue $account 'useDESKeyOnly'
        $protocolTransition = Get-RecordValue $account 'trustedToAuthForDelegation'
        $owner = Get-RecordValue $account 'owner'
        $adminCount = Get-RecordValue $account 'adminCount'
        $missing = [Collections.Generic.List[string]]::new()
        foreach ($flag in @('enabled','doesNotRequirePreAuth','trustedForDelegation','useDESKeyOnly')) {
            if ($null -eq (Get-RecordValue $account $flag)) { $missing.Add($flag) }
        }
        if ($enabled -eq $true -and $kind -eq 'UserService') {
            if ($null -eq $passwordNeverExpires) { $missing.Add('passwordNeverExpires') }
            if ($null -eq $passwordLastSet) { $missing.Add('passwordLastSetUtc') }
        }
        if ($missing.Count -gt 0) {
            Add-AuditFinding $findings 'SA-E03' 'Information' $account 'Missing account evidence' "Unavailable fields: $($missing -join ', ')." 'Collect the missing directory attributes before interpreting absent findings as passing controls.' 'Unknown'
        }
        if ($enabled -eq $true -and $delegation -eq $true) {
            Add-AuditFinding $findings 'SA-001' 'Critical' $account 'Unconstrained delegation enabled' 'trustedForDelegation=true.' 'Validate business necessity; migrate to a more restrictive delegation model with the directory/security owner.'
        }
        if ($enabled -eq $true -and $preAuth -eq $true) {
            Add-AuditFinding $findings 'SA-002' 'Critical' $account 'Kerberos preauthentication disabled' 'doesNotRequirePreAuth=true.' 'Investigate and require Kerberos preauthentication where supported.'
        }
        if ($enabled -eq $true -and $des -eq $true) {
            Add-AuditFinding $findings 'SA-003' 'High' $account 'Legacy DES-only Kerberos flag' 'useDESKeyOnly=true.' 'Review Kerberos encryption configuration and remove legacy DES requirements through change control.'
        }
        if ($enabled -eq $true -and $kind -eq 'UserService' -and $passwordNeverExpires -eq $true) {
            Add-AuditFinding $findings 'SA-004' 'High' $account 'Password set never to expire' 'User-based service account with passwordNeverExpires=true.' 'Document an exception or implement controlled rotation; evaluate migration to gMSA where appropriate.'
        }
        $pwdAge = $null
        if ($kind -eq 'UserService' -and $null -ne $passwordLastSet -and $passwordLastSet -le $now) {
            $pwdAge = [int][math]::Floor(($now - $passwordLastSet).TotalDays)
        }
        if ($enabled -eq $true -and $kind -eq 'UserService' -and $null -ne $pwdAge -and $pwdAge -ge [int](Get-RecordValue $Configuration 'passwordAgeDays')) {
            Add-AuditFinding $findings 'SA-005' 'High' $account 'Password age exceeds review threshold' "Last password set $pwdAge days before assessment (threshold: $((Get-RecordValue $Configuration 'passwordAgeDays')) days)." 'Verify credential rotation requirements and plan an owner-approved change.'
        }
        if ($enabled -eq $true -and $null -ne $lastLogon -and $lastLogon -le $now) {
            $inactiveDays = [int][math]::Floor(($now - $lastLogon).TotalDays)
            if ($inactiveDays -ge [int](Get-RecordValue $Configuration 'inactivityDays')) {
                Add-AuditFinding $findings 'SA-006' 'Medium' $account 'Stale replicated logon indicator' "LastLogonDate is approximately $inactiveDays days old; this is replicated, delayed evidence." 'Validate with service owners and richer authentication logs before disabling access.' 'Approximate'
            }
        }
        if ($enabled -eq $true -and $groups.Count -gt 0) {
            Add-AuditFinding $findings 'SA-007' 'High' $account 'Privileged group membership' "Observed membership: $($groups -join '; ')." 'Confirm least privilege, documented necessity, and an approved owner.'
        }
        if ($enabled -eq $false -and $groups.Count -gt 0) {
            Add-AuditFinding $findings 'SA-008' 'Medium' $account 'Disabled account retains privileged membership' "Disabled account appears in: $($groups -join '; ')." 'Confirm account retirement workflow and remove residual access through approved procedures.'
        }
        if ($enabled -eq $true -and ($targets.Count -gt 0 -or $protocolTransition -eq $true)) {
            Add-AuditFinding $findings 'SA-009' 'Medium' $account 'Constrained delegation requires review' "Configured delegation targets: $($targets -join '; '); protocol transition enabled: $protocolTransition." 'Validate target SPNs and delegation controls with the application and domain owners.'
        }
        if ($enabled -eq $true -and $null -ne $expires -and $expires -le $now) {
            Add-AuditFinding $findings 'SA-010' 'High' $account 'Enabled account past configured expiration date' "Account expiration: $($expires.ToString('yyyy-MM-ddTHH:mm:ssZ'))." 'Review expiration and disable/retire through normal change procedures if no longer required.'
        }
        if ([string]::IsNullOrWhiteSpace([string]$owner)) {
            Add-AuditFinding $findings 'SA-011' 'Low' $account 'No owner recorded in snapshot' 'Business/technical owner field is empty.' 'Assign or verify an accountable owner in the service account inventory.' 'Governance'
        }
        if ($enabled -eq $true -and $kind -eq 'UserService' -and $spns.Count -gt 0 -and $null -ne $pwdAge -and $pwdAge -ge [int](Get-RecordValue $Configuration 'spnPasswordAgeDays')) {
            Add-AuditFinding $findings 'SA-012' 'High' $account 'SPN account with aged password' "SPN count: $($spns.Count); password age: $pwdAge days." 'Prioritize password rotation and strong service-account credentials; validate supported auth paths.'
        }
        if ($enabled -eq $true -and $adminCount -eq 1 -and $groups.Count -eq 0) {
            Add-AuditFinding $findings 'SA-013' 'Low' $account 'adminCount historical privilege indicator' 'adminCount=1; no privileged membership observed in configured groups.' 'Review historical privilege and AdminSDHolder implications; adminCount alone does not prove present privilege.' 'Approximate'
        }
        if ($enabled -eq $true -and $null -eq $lastLogon -and $null -ne $created -and $created -le $now) {
            $age = [int][math]::Floor(($now - $created).TotalDays)
            if ($age -ge [int](Get-RecordValue $Configuration 'inactivityDays')) {
                Add-AuditFinding $findings 'SA-014' 'Low' $account 'No replicated logon timestamp for older account' "Account created $age days ago, but LastLogonDate is not populated." 'Verify service usage through suitable logs and owners; a blank attribute is not proof of inactivity.' 'Approximate'
            }
        }
    }
    $severityOrder = @{ Critical=0; High=1; Medium=2; Low=3; Information=4 }
    $sorted = @($findings.ToArray() | Sort-Object -Property @{Expression={ $severityOrder[[string]$_.Severity] }}, Account, RuleId)
    $counts = [ordered]@{}
    foreach ($severity in @('Critical','High','Medium','Low','Information')) { $counts[$severity] = @($sorted | Where-Object { $_.Severity -eq $severity }).Count }
    $hasEvidenceGap = ($accountStatus -ne 'Complete' -or $groupStatus -ne 'Complete' -or @($sorted | Where-Object { $_.RuleId -eq 'SA-E03' }).Count -gt 0)
    return [pscustomobject][ordered]@{
        Tool = 'Service Account Hygiene Auditor'
        Version = '0.1.0'
        AsOfUtc = $now.ToString('yyyy-MM-ddTHH:mm:ssZ')
        Source = [string](Get-RecordValue $Snapshot 'source')
        Collection = $collection
        Summary = [pscustomobject][ordered]@{
            TotalAccounts = $accounts.Count
            EnabledAccounts = @($accounts | Where-Object { (Get-RecordValue $_ 'enabled') -eq $true }).Count
            TotalFindings = $sorted.Count
            Critical = $counts.Critical
            High = $counts.High
            Medium = $counts.Medium
            Low = $counts.Low
            Information = $counts.Information
            Assessment = $(if ($hasEvidenceGap) { 'Incomplete evidence - review required' } elseif ($sorted.Count -gt 0) { 'Findings require review' } else { 'No configured findings observed' })
        }
        Findings = $sorted
    }
}

function Protect-CsvText {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    $string = [string]$Value
    if ($string -match '^[\s\uFEFF]*[=+@\-]') { return "'$string" }
    return $string
}

function ConvertTo-HtmlSafe {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Export-ServiceAccountHygieneReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Audit, [Parameter(Mandatory)][string]$OutputDirectory)
    $fullOutput = [IO.Path]::GetFullPath($OutputDirectory)
    if (-not (Test-Path -LiteralPath $fullOutput -PathType Container)) { $null = New-Item -ItemType Directory -Path $fullOutput -Force -ErrorAction Stop }
    $stamp = ([datetimeoffset]::UtcNow).ToString('yyyyMMddTHHmmssZ') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $prefix = Join-Path $fullOutput "service-account-audit-$stamp"
    $jsonFile = "$prefix.json"
    $csvFile = "$prefix.csv"
    $htmlFile = "$prefix.html"
    ConvertTo-Json -InputObject $Audit -Depth 14 | Set-Content -LiteralPath $jsonFile -Encoding utf8NoBOM -ErrorAction Stop
    $columns = @('RuleId','Severity','Account','AccountSid','AccountType','Title','Evidence','RecommendedAction','Confidence')
    $rows = @($Audit.Findings | ForEach-Object {
        $item = [ordered]@{}
        foreach ($column in $columns) { $item[$column] = Protect-CsvText (Get-RecordValue $_ $column) }
        [pscustomobject]$item
    })
    if ($rows.Count -gt 0) {
        $rows | Export-Csv -LiteralPath $csvFile -NoTypeInformation -Encoding utf8NoBOM -ErrorAction Stop
    } else {
        ('"' + ($columns -join '","') + '"') | Set-Content -LiteralPath $csvFile -Encoding utf8NoBOM -ErrorAction Stop
    }
    $summary = $Audit.Summary
    $tableRows = [Collections.Generic.List[string]]::new()
    foreach ($item in $Audit.Findings) {
        $cells = foreach ($column in @('Severity','RuleId','Account','AccountType','Title','Evidence','RecommendedAction','Confidence')) {
            '<td>' + (ConvertTo-HtmlSafe (Get-RecordValue $item $column)) + '</td>'
        }
        $severity = [string]$item.Severity
        $tableRows.Add('<tr class="sev-' + $severity.ToLowerInvariant() + '">' + ($cells -join '') + '</tr>')
    }
    $ifEmpty = if ($tableRows.Count -eq 0) { '<tr><td colspan="8">No findings in configured scope. Confirm collection completeness before using this as compliance evidence.</td></tr>' } else { $tableRows -join "`n" }
    $title = ConvertTo-HtmlSafe $Audit.Tool
    $status = ConvertTo-HtmlSafe $summary.Assessment
    $asOf = ConvertTo-HtmlSafe $Audit.AsOfUtc
    $source = ConvertTo-HtmlSafe $Audit.Source
    $countsText = "Accounts: $($summary.TotalAccounts) · Findings: $($summary.TotalFindings) · Critical: $($summary.Critical) · High: $($summary.High) · Medium: $($summary.Medium) · Low: $($summary.Low) · Information: $($summary.Information)"
    $countsHtml = ConvertTo-HtmlSafe $countsText
    $page = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>$title — read-only audit</title>
<style>
:root {color-scheme:light} body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:#f7f6f2;color:#232832;max-width:1200px;margin:0 auto;padding:34px 22px;line-height:1.5}
header{border-bottom:2px solid #d8c8aa;margin-bottom:24px;padding-bottom:18px}h1{font-size:clamp(24px,4vw,40px);margin:0 0 7px}p{margin:8px 0}small{color:#626a73}.metric{display:inline-block;border:1px solid #dedad2;background:#fff;border-radius:9px;padding:12px 16px;margin:8px 12px 12px 0}
.status{padding:12px 16px;background:#fff;border-left:4px solid #ab8050;margin:18px 0} table{border-collapse:collapse;width:100%;font-size:13px;background:white;table-layout:auto}th,td{border:1px solid #e7e3da;padding:10px;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#ece8df}tr.sev-critical td:first-child{color:#a72e23;font-weight:700}tr.sev-high td:first-child{color:#ad581e;font-weight:700}tr.sev-medium td:first-child{color:#88640b;font-weight:700}tr.sev-low td:first-child{color:#356079;font-weight:700}.table-wrap{overflow:auto}footer{margin-top:24px;color:#555;font-size:12px}
</style></head><body>
<header><small>ISGIN · IAM OPERATIONS · OFFLINE EVIDENCE VIEW</small><h1>$title</h1><p>Assessment time (UTC): $asOf · Source: $source</p></header>
<div class="status"><strong>Assessment:</strong> $status<br><span>$countsHtml</span></div>
<section><h2>Observations</h2><p>These are review candidates, not proof of compromise. Replicated logon timestamps are approximate. Unknown or uncollected attributes never count as passing checks.</p>
<div class="table-wrap"><table><thead><tr><th>Severity</th><th>Rule</th><th>Account</th><th>Type</th><th>Finding</th><th>Evidence</th><th>Action</th><th>Confidence</th></tr></thead><tbody>$ifEmpty</tbody></table></div></section>
<footer>Read-only analyzer. Reports may contain sensitive directory metadata. Keep real exports out of source control and handle under your organization's security policy.</footer>
</body></html>
"@
    $page | Set-Content -LiteralPath $htmlFile -Encoding utf8NoBOM -ErrorAction Stop
    return [pscustomobject][ordered]@{ Json=$jsonFile; Csv=$csvFile; Html=$htmlFile }
}

function ConvertTo-AdUtcString {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetimeoffset]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
    if ($Value -is [datetime]) {
        if ($Value.Year -lt 1970) { return $null }
        return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    return $null
}

function ConvertTo-LdapLiteral {
    param([Parameter(Mandatory)][string]$Value)
    return $Value.Replace('\','\5c').Replace('*','\2a').Replace('(','\28').Replace(')','\29').Replace([string][char]0,'\00')
}

function ConvertFrom-AdServiceObject {
    param([Parameter(Mandatory)][object]$AdObject, [Parameter(Mandatory)][string]$AccountType)
    $sidObject = Get-RecordValue $AdObject 'SID'
    $sid = if ($null -eq $sidObject) { '' } elseif ($null -ne $sidObject.PSObject.Properties['Value']) { [string]$sidObject.Value } else { [string]$sidObject }
    $rawSpns = Get-RecordValue $AdObject 'ServicePrincipalNames'
    $rawTargets = Get-RecordValue $AdObject 'msDS-AllowedToDelegateTo'
    $spn = @(foreach ($v in $rawSpns) { if (-not [string]::IsNullOrWhiteSpace([string]$v)) { [string]$v } })
    $targets = @(foreach ($v in $rawTargets) { if (-not [string]::IsNullOrWhiteSpace([string]$v)) { [string]$v } })
    $managedBy = Get-RecordValue $AdObject 'ManagedBy'
    $admin = Get-RecordValue $AdObject 'adminCount'
    return [pscustomobject][ordered]@{
        sid = $sid
        samAccountName = [string](Get-RecordValue $AdObject 'SamAccountName')
        accountType = $AccountType
        enabled = Get-RecordValue $AdObject 'Enabled'
        owner = $(if ($null -eq $managedBy) { $null } else { [string]$managedBy })
        createdUtc = ConvertTo-AdUtcString (Get-RecordValue $AdObject 'whenCreated')
        lastLogonUtc = ConvertTo-AdUtcString (Get-RecordValue $AdObject 'LastLogonDate')
        passwordLastSetUtc = ConvertTo-AdUtcString (Get-RecordValue $AdObject 'PasswordLastSet')
        accountExpiresUtc = ConvertTo-AdUtcString (Get-RecordValue $AdObject 'AccountExpirationDate')
        passwordNeverExpires = Get-RecordValue $AdObject 'PasswordNeverExpires'
        doesNotRequirePreAuth = Get-RecordValue $AdObject 'DoesNotRequirePreAuth'
        trustedForDelegation = Get-RecordValue $AdObject 'TrustedForDelegation'
        trustedToAuthForDelegation = Get-RecordValue $AdObject 'TrustedToAuthForDelegation'
        useDESKeyOnly = Get-RecordValue $AdObject 'UseDESKeyOnly'
        adminCount = $(if ($null -eq $admin) { $null } else { [int]$admin })
        servicePrincipalNames = @($spn)
        delegationTargets = @($targets)
        privilegedGroups = @()
    }
}

function Get-AdServiceAccountHygieneSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$LegacySearchBase,
        [Parameter(Mandatory)][string]$ManagedSearchBase,
        [Parameter(Mandatory)][object]$Configuration,
        [string]$Server
    )
    Assert-Configuration $Configuration
    if (-not $IsWindows) { throw 'Active Directory live mode requires Windows with RSAT/ActiveDirectory module.' }
    Import-Module ActiveDirectory -ErrorAction Stop
    $prefixes = Get-StringArray (Get-RecordValue $Configuration 'legacySamPrefixes') 'legacySamPrefixes'
    if ($prefixes.Count -eq 0) { throw 'Configure at least one legacySamPrefixes value before AD collection.' }
    $ldapTerms = @(foreach ($prefix in $prefixes) { '(sAMAccountName=' + (ConvertTo-LdapLiteral $prefix) + '*)' })
    $ldap = if ($ldapTerms.Count -eq 1) { $ldapTerms[0] } else { '(|' + ($ldapTerms -join '') + ')' }
    $props = @('whenCreated','PasswordLastSet','LastLogonDate','PasswordNeverExpires','DoesNotRequirePreAuth','TrustedForDelegation','TrustedToAuthForDelegation','UseDESKeyOnly','ServicePrincipalNames','msDS-AllowedToDelegateTo','AccountExpirationDate','adminCount','ManagedBy')
    $queryArgs = @{ErrorAction='Stop';Properties=$props}
    if (-not [string]::IsNullOrWhiteSpace($Server)) { $queryArgs.Server = $Server }
    # Fail closed on collection errors rather than reporting a partial directory as clean.
    $users = @(Get-ADUser -LDAPFilter $ldap -SearchBase $LegacySearchBase @queryArgs)
    $managed = @(Get-ADServiceAccount -Filter '*' -SearchBase $ManagedSearchBase @queryArgs)
    $accounts = [Collections.Generic.List[object]]::new()
    foreach ($entry in $users) { $accounts.Add((ConvertFrom-AdServiceObject $entry 'UserService')) }
    foreach ($entry in $managed) {
        $kind = if ([string](Get-RecordValue $entry 'ObjectClass') -eq 'msDS-GroupManagedServiceAccount') { 'gMSA' } else { 'sMSA' }
        $accounts.Add((ConvertFrom-AdServiceObject $entry $kind))
    }
    if ($accounts.Count -eq 0) { throw 'No accounts returned in the selected search bases. Check scope; not writing a false-clean report.' }
    $groups = Get-StringArray (Get-RecordValue $Configuration 'privilegedGroups') 'privilegedGroups'
    $membershipStatus = 'NotCollected'
    $groupErrors = [Collections.Generic.List[string]]::new()
    if ($groups.Count -gt 0) {
        $membershipStatus = 'Complete'
        $groupArgs = @{ErrorAction='Stop'}
        if (-not [string]::IsNullOrWhiteSpace($Server)) { $groupArgs.Server = $Server }
        $bySid = @{}
        foreach ($a in $accounts) { $bySid[$a.sid] = $a }
        foreach ($groupName in $groups) {
            try {
                $members = @(Get-ADGroupMember -Identity $groupName -Recursive @groupArgs)
                foreach ($member in $members) {
                    $sidObj = Get-RecordValue $member 'SID'
                    $memberSid = if ($null -eq $sidObj) { '' } elseif ($null -ne $sidObj.PSObject.Properties['Value']) { [string]$sidObj.Value } else { [string]$sidObj }
                    if ($bySid.ContainsKey($memberSid)) {
                        $bySid[$memberSid].privilegedGroups = @($bySid[$memberSid].privilegedGroups) + @($groupName)
                    }
                }
            } catch {
                $membershipStatus = 'Partial'
                $groupErrors.Add("Unable to query configured privileged group '$groupName'.")
            }
        }
    }
    return [pscustomobject][ordered]@{
        schemaVersion=1
        generatedUtc=[datetimeoffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        source='ActiveDirectory-read-only'
        collection=[pscustomobject][ordered]@{
            accountsStatus='Complete'
            privilegedMembershipStatus=$membershipStatus
            legacySearchBase=$LegacySearchBase
            managedSearchBase=$ManagedSearchBase
            queriedPrivilegedGroups=@($groups)
            warnings=@($groupErrors.ToArray())
        }
        accounts=@($accounts.ToArray())
    }
}

Export-ModuleMember -Function Invoke-ServiceAccountHygieneAnalysis, Export-ServiceAccountHygieneReport, Get-AdServiceAccountHygieneSnapshot
