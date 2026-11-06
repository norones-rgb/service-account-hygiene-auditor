#Requires -Version 7.2
BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $root 'src/ServiceAccountHygiene.psm1') -Force
    $fixture = Join-Path $root 'sample-data/service-accounts.synthetic.json'
    $configFile = Join-Path $root 'config/default.json'
    $snapshot = Get-Content $fixture -Raw | ConvertFrom-Json -AsHashtable
    $config = Get-Content $configFile -Raw | ConvertFrom-Json -AsHashtable
    $asOf = '2026-11-05T19:00:00Z'
}
Describe 'Synthetic fixture and risk rules' {
    It 'produces the locked total and severity distribution' {
        $result = Invoke-ServiceAccountHygieneAnalysis -Snapshot $snapshot -Configuration $config -AsOfUtc $asOf
        $result.Summary.TotalAccounts | Should -Be 11
        $result.Summary.TotalFindings | Should -Be 20
        $result.Summary.Critical | Should -Be 2
        $result.Summary.High | Should -Be 9
        $result.Summary.Medium | Should -Be 3
        $result.Summary.Low | Should -Be 5
        $result.Summary.Information | Should -Be 1
    }
    It 'never applies legacy password-age findings to gMSA or sMSA' {
        $result = Invoke-ServiceAccountHygieneAnalysis -Snapshot $snapshot -Configuration $config -AsOfUtc $asOf
        @($result.Findings | Where-Object { $_.AccountType -in @('gMSA','sMSA') -and $_.RuleId -in @('SA-004','SA-005','SA-012') }).Count | Should -Be 0
    }
    It 'does not claim unknown attributes are secure' {
        $result = Invoke-ServiceAccountHygieneAnalysis -Snapshot $snapshot -Configuration $config -AsOfUtc $asOf
        @($result.Findings | Where-Object { $_.RuleId -eq 'SA-E03' -and $_.Account -eq 'svc_missing_evidence' }).Count | Should -Be 1
        $result.Summary.Assessment | Should -Be 'Incomplete evidence - review required'
    }
    It 'flags disabled accounts still retaining configured privilege' {
        $result = Invoke-ServiceAccountHygieneAnalysis -Snapshot $snapshot -Configuration $config -AsOfUtc $asOf
        @($result.Findings | Where-Object { $_.RuleId -eq 'SA-008' -and $_.Account -eq 'svc_retired' }).Count | Should -Be 1
    }
    It 'separates missing logons from a confirmed stale replicated logon indicator' {
        $result = Invoke-ServiceAccountHygieneAnalysis -Snapshot $snapshot -Configuration $config -AsOfUtc $asOf
        @($result.Findings | Where-Object { $_.Account -eq 'svc_missing_evidence' -and $_.RuleId -eq 'SA-006' }).Count | Should -Be 0
        @($result.Findings | Where-Object { $_.Account -eq 'svc_missing_evidence' -and $_.RuleId -eq 'SA-014' }).Count | Should -Be 1
    }
}
Describe 'Input validation and evidence coverage' {
    It 'rejects boolean strings rather than interpreting a value of false as true' {
        $changed = $snapshot | ConvertTo-Json -Depth 12 | ConvertFrom-Json -AsHashtable
        $changed.accounts[0].enabled = 'false'
        { Invoke-ServiceAccountHygieneAnalysis -Snapshot $changed -Configuration $config -AsOfUtc $asOf } | Should -Throw
    }
    It 'rejects null group evidence rather than treating it as an empty membership list' {
        $changed = $snapshot | ConvertTo-Json -Depth 12 | ConvertFrom-Json -AsHashtable
        $changed.accounts[0].privilegedGroups = $null
        { Invoke-ServiceAccountHygieneAnalysis -Snapshot $changed -Configuration $config -AsOfUtc $asOf } | Should -Throw
    }
    It 'rejects duplicate SIDs' {
        $changed = $snapshot | ConvertTo-Json -Depth 12 | ConvertFrom-Json -AsHashtable
        $changed.accounts[1].sid = $changed.accounts[0].sid
        { Invoke-ServiceAccountHygieneAnalysis -Snapshot $changed -Configuration $config -AsOfUtc $asOf } | Should -Throw
    }
    It 'rejects missing timezone information' {
        { Invoke-ServiceAccountHygieneAnalysis -Snapshot $snapshot -Configuration $config -AsOfUtc '2026-11-05T19:00:00' } | Should -Throw
    }
    It 'reports incomplete group evidence even when the account list was successful' {
        $changed = $snapshot | ConvertTo-Json -Depth 12 | ConvertFrom-Json -AsHashtable
        $changed.collection.privilegedMembershipStatus = 'NotCollected'
        $result = Invoke-ServiceAccountHygieneAnalysis -Snapshot $changed -Configuration $config -AsOfUtc $asOf
        $result.Summary.Assessment | Should -Be 'Incomplete evidence - review required'
        @($result.Findings | Where-Object RuleId -eq 'SA-E02').Count | Should -Be 1
    }
    It 'rejects blank snapshots to prevent false clean results' {
        $changed = $snapshot | ConvertTo-Json -Depth 12 | ConvertFrom-Json -AsHashtable
        $changed.accounts = @()
        { Invoke-ServiceAccountHygieneAnalysis -Snapshot $changed -Configuration $config -AsOfUtc $asOf } | Should -Throw
    }
    It 'rejects unsafe LDAP prefixes from configuration' {
        $changedConfig = $config | ConvertTo-Json -Depth 12 | ConvertFrom-Json -AsHashtable
        $changedConfig.legacySamPrefixes = @('svc_)(objectClass=*)')
        { Invoke-ServiceAccountHygieneAnalysis -Snapshot $snapshot -Configuration $changedConfig -AsOfUtc $asOf } | Should -Throw
    }
}
Describe 'Report exports' {
    It 'exports JSON, CSV and offline HTML artifacts' {
        $path = Join-Path $TestDrive 'export'
        $result = Invoke-ServiceAccountHygieneAnalysis -Snapshot $snapshot -Configuration $config -AsOfUtc $asOf
        $artifacts = Export-ServiceAccountHygieneReport -Audit $result -OutputDirectory $path
        Test-Path -LiteralPath $artifacts.Json | Should -BeTrue
        Test-Path -LiteralPath $artifacts.Csv | Should -BeTrue
        Test-Path -LiteralPath $artifacts.Html | Should -BeTrue
        $jsonResult = Get-Content -LiteralPath $artifacts.Json -Raw | ConvertFrom-Json
        $jsonResult.Summary.TotalAccounts | Should -Be 11
    }
    It 'escapes HTML content and spreadsheet formulas' {
        $changed = $snapshot | ConvertTo-Json -Depth 12 | ConvertFrom-Json -AsHashtable
        $changed.accounts[0].samAccountName = '=HYPERLINK("https://bad.test")<img src=x>'
        $result = Invoke-ServiceAccountHygieneAnalysis -Snapshot $changed -Configuration $config -AsOfUtc $asOf
        $artifacts = Export-ServiceAccountHygieneReport -Audit $result -OutputDirectory (Join-Path $TestDrive 'injection')
        $html = Get-Content -LiteralPath $artifacts.Html -Raw
        $csv = Get-Content -LiteralPath $artifacts.Csv -Raw
        $html | Should -Not -Match '<img src=x>'
        $html | Should -Match '&lt;img'
        $csv | Should -Match "'=HYPERLINK"
    }
    It 'writes a header-only CSV for a zero finding result' {
        $safe = $snapshot | ConvertTo-Json -Depth 12 | ConvertFrom-Json -AsHashtable
        foreach ($a in $safe.accounts) {
            $a.enabled = $false
            $a.owner = 'Assigned'
            $a.privilegedGroups = @()
            $a.doesNotRequirePreAuth = $false
            $a.trustedForDelegation = $false
            $a.useDESKeyOnly = $false
        }
        $clean = Invoke-ServiceAccountHygieneAnalysis -Snapshot $safe -Configuration $config -AsOfUtc $asOf
        $clean.Summary.TotalFindings | Should -Be 0
        $artifacts = Export-ServiceAccountHygieneReport -Audit $clean -OutputDirectory (Join-Path $TestDrive 'clean')
        @(Get-Content -LiteralPath $artifacts.Csv).Count | Should -Be 1
    }
}

Describe 'Entry point integration' {
    It 'runs the offline demo without any Active Directory connection' {
        $output = Join-Path $TestDrive 'entrypoint'
        $result = & (Join-Path $root 'Invoke-ServiceAccountHygieneAudit.ps1') -Mode Demo -AsOfUtc $asOf -OutputDirectory $output
        $result.Summary.TotalFindings | Should -Be 20
        Test-Path -LiteralPath $result.Reports.Html | Should -BeTrue
    }
}
