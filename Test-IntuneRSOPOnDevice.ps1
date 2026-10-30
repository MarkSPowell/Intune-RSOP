<#
.SYNOPSIS
Checks on the endpoint that the settings Intune reports as applied are really in effect.

.DESCRIPTION
Reads the expected-state file written by Get-IntuneRSOPData -ExportExpectedState and compares each
Policy CSP setting (./Device or ./User/Vendor/MSFT/Policy/Config/<Area>/<Setting>) with the value
Windows recorded under HKLM:\SOFTWARE\Microsoft\PolicyManager\current.

Results:
  Applied     The device holds the value Intune sent.
  Different   The setting is there with another value (another policy, GPO, or a local change won).
  Missing     Nothing is recorded for the setting.
  Present     The setting is there but the value can't be compared (ADMX-backed settings).
  NotChecked  Not a Policy CSP setting (BitLocker, Firewall, Defender CSP and so on keep their state elsewhere).

To use it as an Intune remediation detection script, paste the expected-state JSON into
$EmbeddedExpectedState below. It then writes a one-line summary (read it back from Graph in
managedDevices/{id}/deviceHealthScriptStates, preRemediationDetectionScriptOutput) and exits 1
when anything is Different or Missing.

.EXAMPLE
.\Test-IntuneRSOPOnDevice.ps1 -ExpectedStatePath C:\Temp\PC-0042-expected.json | Out-GridView
#>

param (
    [string]$ExpectedStatePath
)

$EmbeddedExpectedState = @'
'@

$policyManager = 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current'

if ($ExpectedStatePath) {
    $expectedJson = Get-Content -Path $ExpectedStatePath -Raw
    $summaryMode = $false
}
elseif ($EmbeddedExpectedState.Trim()) {
    $expectedJson = $EmbeddedExpectedState
    $summaryMode = $true
}
else {
    throw 'Pass -ExpectedStatePath, or paste the expected state into $EmbeddedExpectedState.'
}
# Windows PowerShell's ConvertFrom-Json writes a JSON array out as one object, so store it first and let
# the pipeline below unroll it. An empty array comes back as $null, which the filter drops.
$parsedSettings = $expectedJson | ConvertFrom-Json
$expectedSettings = @($parsedSettings | Where-Object { $_ })

# User-scoped policies are stored under the user's SID. Running as SYSTEM there's no "current user",
# so check every SID that has a PolicyManager key.
$userScopes = @(Get-ChildItem -Path $policyManager -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -like 'S-1-*' } |
    ForEach-Object { $_.PSChildName })

$results = foreach ($setting in $expectedSettings) {
    $result = [PSCustomObject]@{
        PolicyName    = $setting.PolicyName
        SettingName   = $setting.SettingName
        CspPath       = $setting.CspPath
        ExpectedValue = $setting.ExpectedDeviceValue
        DeviceValue   = $null
        Scope         = $null
        Result        = 'NotChecked'
    }

    # -match (not -notmatch) so $Matches is filled in for the lines below.
    if (-not ($setting.CspPath -match '^\./(Device|User)/Vendor/MSFT/Policy/Config/([^/]+)/([^/]+)$')) {
        $result
        continue
    }
    $isDevice = $Matches[1] -eq 'Device'
    $area = $Matches[2]
    $name = $Matches[3]

    $scopes = $userScopes
    if ($isDevice) { $scopes = @('device') }

    $found = @(foreach ($scope in $scopes) {
            $key = Get-ItemProperty -Path "$policyManager\$scope\$area" -Name $name -ErrorAction SilentlyContinue
            if ($key) {
                [PSCustomObject]@{ Scope = $scope; Value = $key.$name }
            }
        })

    if ($found.Count -eq 0) {
        $result.Result = 'Missing'
        $result
        continue
    }

    # ADMX-backed settings carry XML like <enabled/><data id=... />; Windows doesn't store that string back.
    $expected = [string]$setting.ExpectedDeviceValue
    $admxBacked = $expected.TrimStart().StartsWith('<')

    $match = $found | Where-Object { [string]$_.Value -eq $expected } | Select-Object -First 1
    $shown = $match
    if (-not $shown) { $shown = $found[0] }
    $result.DeviceValue = $shown.Value
    $result.Scope = $shown.Scope

    if ($admxBacked) {
        $result.Result = 'Present'
    }
    elseif ($match) {
        $result.Result = 'Applied'
    }
    else {
        $result.Result = 'Different'
    }
    $result
}

if (-not $summaryMode) {
    $results
    return
}

# Remediation output is short, so report counts plus as many problem settings as fit.
$counts = $results | Group-Object Result | ForEach-Object { "$($_.Name)=$($_.Count)" }
$problems = @($results | Where-Object { $_.Result -in 'Different', 'Missing' })
$summary = ($counts -join ' ')
if ($problems.Count -gt 0) {
    $details = $problems | ForEach-Object { "$($_.Result): $($_.CspPath -replace '^\./(Device|User)/Vendor/MSFT/Policy/Config/', '') ($($_.PolicyName))" }
    $summary = "$summary | $($details -join '; ')"
}
if ($summary.Length -gt 2000) {
    $summary = $summary.Substring(0, 1997) + '...'
}
Write-Output $summary

if ($problems.Count -gt 0) {
    exit 1
}
exit 0
