#Requires -Version 7.2
[CmdletBinding()]
param(
    [ValidateSet('Demo','Snapshot','AD')][string]$Mode = 'Demo',
    [string]$SnapshotPath,
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config/default.json'),
    [string]$OutputDirectory = (Join-Path $PSScriptRoot 'output'),
    [string]$AsOfUtc = ([datetimeoffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')),
    [string]$LegacySearchBase,
    [string]$ManagedSearchBase,
    [string]$Server
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'src/ServiceAccountHygiene.psm1') -Force
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { throw "Configuration file not found: $ConfigPath" }
$config = Get-Content -LiteralPath $ConfigPath -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable
switch ($Mode) {
    'Demo' {
        $path = Join-Path $PSScriptRoot 'sample-data/service-accounts.synthetic.json'
        $snapshot = Get-Content -LiteralPath $path -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable
    }
    'Snapshot' {
        if ([string]::IsNullOrWhiteSpace($SnapshotPath)) { throw 'Mode Snapshot requires -SnapshotPath.' }
        $snapshot = Get-Content -LiteralPath $SnapshotPath -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable
    }
    'AD' {
        if ([string]::IsNullOrWhiteSpace($LegacySearchBase) -or [string]::IsNullOrWhiteSpace($ManagedSearchBase)) {
            throw 'Mode AD requires both -LegacySearchBase and -ManagedSearchBase to explicitly bound collection.'
        }
        $params = @{LegacySearchBase=$LegacySearchBase;ManagedSearchBase=$ManagedSearchBase;Configuration=$config}
        if ($Server) { $params.Server = $Server }
        $snapshot = Get-AdServiceAccountHygieneSnapshot @params
    }
}
$report = Invoke-ServiceAccountHygieneAnalysis -Snapshot $snapshot -Configuration $config -AsOfUtc $AsOfUtc
$paths = Export-ServiceAccountHygieneReport -Audit $report -OutputDirectory $OutputDirectory
[pscustomobject][ordered]@{Summary=$report.Summary; Reports=$paths}
