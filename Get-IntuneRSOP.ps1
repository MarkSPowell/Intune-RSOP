<#
.SYNOPSIS
Lists every Intune configuration setting applied to a device, and the policy that sets it.

.DESCRIPTION
This script helps IT administrators analyze and audit Intune assignments by helping to find the specific
Intune Policy causing an issue with a specific computer.

For Settings Catalog policies it also looks up the configured value, the policy priority and the CSP path
the setting writes to on the device. Export those with -ExportExpectedState and run
Test-IntuneRSOPOnDevice.ps1 on the endpoint to check the setting is really in effect there.

Only needs the Microsoft.Graph.Authentication module. Every call goes through Invoke-MgGraphRequest.

.EXAMPLE
. .\Get-IntuneRSOP.ps1
Connect-MgGraph -Scopes DeviceManagementConfiguration.Read.All, DeviceManagementManagedDevices.Read.All
Get-IntuneRSOPData -DeviceName PC-0042 | Out-GridView

.EXAMPLE
Get-IntuneRSOPData -DeviceName PC-0042 -ExportExpectedState C:\Temp\PC-0042-expected.json
#>

#Requires -Modules Microsoft.Graph.Authentication

#Connect-MgGraph -ClientId $ClientId -TenantId $TenantId

$script:GraphBase = 'https://graph.microsoft.com/beta'
$script:SettingsCatalogCache = @{}

# Follows @odata.nextLink so a list call never stops at the first page.
function Get-GraphCollection {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )
    $next = $Uri
    while ($next) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject
        if ($page.value) { $page.value }
        $next = $page.'@odata.nextLink'
    }
}

# Calls one of the deviceManagement/reports actions and returns one object per row.
# The reports answer with a stream, not JSON, so Invoke-MgGraphRequest needs -OutputType HttpResponseMessage.
# Columns don't come back in the order they were selected, so they're named from the Schema in the response.
# Pages with skip/top until TotalRowCount is reached; a single call stops at $PageSize rows.
function Invoke-IntuneReport {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ReportName,
        [Parameter(Mandatory = $true)]
        [string]$Filter,
        [string[]]$Select,
        [string[]]$OrderBy,
        [int]$PageSize = 50
    )

    $skip = 0
    do {
        $body = @{
            filter = $Filter
            skip   = $skip
            top    = $PageSize
        }
        if ($Select) { $body.select = $Select }
        if ($OrderBy) { $body.orderBy = $OrderBy }

        $response = Invoke-MgGraphRequest -Method POST -Uri "$script:GraphBase/deviceManagement/reports/$ReportName" `
            -Body ($body | ConvertTo-Json) -ContentType 'application/json' -OutputType HttpResponseMessage
        $report = $response.Content.ReadAsStringAsync().Result | ConvertFrom-Json

        $columns = @($report.Schema.Column)
        $rows = @($report.Values)
        foreach ($row in $rows) {
            $record = [ordered]@{}
            for ($i = 0; $i -lt $columns.Count; $i++) {
                $record[$columns[$i]] = $row[$i]
            }
            [PSCustomObject]$record
        }

        $skip += $PageSize
    } while ($rows.Count -gt 0 -and $skip -lt $report.TotalRowCount)
}

# Report enums come with a readable copy in <Column>_loc; prefer it when it's there.
function Get-ReportValue {
    param (
        [Parameter(Mandatory = $true)]
        $Row,
        [Parameter(Mandatory = $true)]
        [string]$Column
    )
    $localized = $Row.PSObject.Properties["$($Column)_loc"]
    if ($localized -and $localized.Value) {
        return $localized.Value
    }
    return $Row.$Column
}

function Get-IntuneDeviceByName {
    param (
        [Parameter(Mandatory = $true)]
        [string]$DeviceName
    )
    $filter = [uri]::EscapeDataString("deviceName eq '$($DeviceName.Replace("'", "''"))'")
    $devices = @(Get-GraphCollection -Uri "$script:GraphBase/deviceManagement/managedDevices?`$filter=$filter&`$select=id,deviceName,userPrincipalName,lastSyncDateTime,operatingSystem")

    if ($devices.Count -eq 0) {
        throw "No Intune device named '$DeviceName'."
    }
    # Re-enrolled devices leave stale records with the same name; the one that synced last is the live one.
    $device = $devices | Sort-Object lastSyncDateTime -Descending | Select-Object -First 1
    if ($devices.Count -gt 1) {
        Write-Warning "$($devices.Count) devices are named '$DeviceName'. Using $($device.id), last synced $($device.lastSyncDateTime)."
    }
    return $device
}

Function Get-IntuneConfigurationPolicyForDevice {
    param (
        [Parameter(Mandatory = $true)]
        [string]$DeviceID
    )

    $filter = "((PolicyBaseTypeName eq 'Microsoft.Management.Services.Api.DeviceConfiguration') or (PolicyBaseTypeName eq 'DeviceManagementConfigurationPolicy') or (PolicyBaseTypeName eq 'DeviceConfigurationAdmxPolicy') or (PolicyBaseTypeName eq 'Microsoft.Management.Services.Api.DeviceManagementIntent')) and (IntuneDeviceId eq '$DeviceID')"
    $select = @(
        "IntuneDeviceId"
        "PolicyBaseTypeName"
        "PolicyId"
        "PolicyStatus"
        "UPN"
        "UserId"
        "PspdpuLastModifiedTimeUtc"
        "PolicyName"
        "UnifiedPolicyType"
    )

    Invoke-IntuneReport -ReportName 'getConfigurationPoliciesReportForDevice' -Filter $filter -Select $select -OrderBy 'PolicyName'
}

Function Get-IntunePolicySettingStatus {
    param (
        [Parameter(Mandatory = $true)]
        [string]$DeviceID,
        [Parameter(Mandatory = $true)]
        [string]$PolicyId,
        [Parameter(Mandatory = $true)]
        [string]$UserID,
        [Parameter(Mandatory = $true)]
        [string]$PolicyBaseTypeName
    )

    $filter = "(PolicyId eq '$PolicyId') and (DeviceId eq '$DeviceID') and (UserId eq '$UserID')"

    switch ($PolicyBaseTypeName) {
        "Microsoft.Management.Services.Api.DeviceConfiguration" {
            Invoke-IntuneReport -ReportName 'getConfigurationSettingNonComplianceReport' -Filter $filter -Select @(
                "SettingName"
                "SettingStatus"
                "ErrorCode"
                "SettingInstanceId"
                "SettingInstancePath"
            )
        }
        "DeviceManagementConfigurationPolicy" {
            Invoke-IntuneReport -ReportName 'getConfigurationSettingsReport' -Filter $filter -Select @(
                "SettingName"
                "SettingStatus"
                "ErrorCode"
                "SettingId"
                "SettingInstanceId"
            )
        }
        "DeviceConfigurationAdmxPolicy" {
            Invoke-IntuneReport -ReportName 'getGroupPolicySettingsDeviceSettingsReport' -Filter $filter -Select @(
                "SettingName"
                "SettingStatus"
                "ErrorCode"
                "SettingId"
                "SettingInstanceId"
            )
        }
        "Microsoft.Management.Services.Api.DeviceManagementIntent" {
            # Untested: the docs don't list this report's columns, so ask for all of them and let the Schema name them.
            # If the filter is rejected, run it once by hand and check the column names it returns.
            Invoke-IntuneReport -ReportName 'getDeviceManagementIntentSettingsReport' -Filter $filter
        }
        default {
            Write-Warning "No setting report known for policy type '$PolicyBaseTypeName'."
        }
    }
}

# Walks one Settings Catalog setting instance (and its children) and returns one object per setting
# that carries a value, with the value Windows should end up holding and the CSP path it lives at.
function ConvertFrom-SettingInstance {
    param (
        [Parameter(Mandatory = $true)]
        $Instance,
        [Parameter(Mandatory = $true)]
        [hashtable]$Definitions
    )

    $definition = $Definitions[$Instance.settingDefinitionId]
    $configuredValue = $null
    $expectedValue = $null
    $hasValue = $false
    $comparable = $false
    $children = @()

    switch -Wildcard ($Instance.'@odata.type') {
        '*ChoiceSettingInstance' {
            $hasValue = $true
            $itemId = $Instance.choiceSettingValue.value
            $option = $null
            if ($definition) {
                $option = $definition.options | Where-Object { $_.itemId -eq $itemId } | Select-Object -First 1
            }
            if ($option) {
                $configuredValue = $option.displayName
                # The device value comes from the option definition, not from the end of the itemId string.
                $expectedValue = $option.optionValue.value
                $comparable = $true
            }
            else {
                $configuredValue = $itemId
            }
            $children = @($Instance.choiceSettingValue.children)
        }
        '*SimpleSettingInstance' {
            $hasValue = $true
            $configuredValue = $Instance.simpleSettingValue.value
            $expectedValue = $configuredValue
            # Secret values come back masked, so there's nothing to compare against.
            $comparable = $Instance.simpleSettingValue.'@odata.type' -notlike '*SecretSettingValue'
        }
        '*SimpleSettingCollectionInstance' {
            $hasValue = $true
            $configuredValue = @($Instance.simpleSettingCollectionValue | ForEach-Object { $_.value }) -join '; '
        }
        '*ChoiceSettingCollectionInstance' {
            $hasValue = $true
            $configuredValue = @($Instance.choiceSettingCollectionValue | ForEach-Object { $_.value }) -join '; '
            $children = @($Instance.choiceSettingCollectionValue | ForEach-Object { $_.children })
        }
        '*GroupSettingInstance' {
            $children = @($Instance.groupSettingValue.children)
        }
        '*GroupSettingCollectionInstance' {
            $children = @($Instance.groupSettingCollectionValue | ForEach-Object { $_.children })
        }
    }

    if ($hasValue) {
        $cspPath = $null
        # An offsetUri with {placeholders} needs values from elsewhere in the policy; leave those out.
        if ($definition -and $definition.baseUri -and $definition.offsetUri -and $definition.offsetUri -notmatch '\{') {
            $cspPath = "$($definition.baseUri.TrimEnd('/'))/$($definition.offsetUri.TrimStart('/'))"
        }
        $displayName = $Instance.settingDefinitionId
        if ($definition) { $displayName = $definition.displayName }

        [PSCustomObject]@{
            SettingDefinitionId = $Instance.settingDefinitionId
            DisplayName         = $displayName
            ConfiguredValue     = $configuredValue
            ExpectedDeviceValue = $expectedValue
            Comparable          = $comparable
            CspPath             = $cspPath
        }
    }

    foreach ($child in $children) {
        if ($child) {
            ConvertFrom-SettingInstance -Instance $child -Definitions $Definitions
        }
    }
}

# Reads a Settings Catalog policy once: its priority, and every setting's value and CSP path.
# Cached by policy ID, because the same policies show up on every device.
function Get-IntuneSettingsCatalogPolicyDetail {
    param (
        [Parameter(Mandatory = $true)]
        [string]$PolicyId
    )

    if ($script:SettingsCatalogCache.ContainsKey($PolicyId)) {
        return $script:SettingsCatalogCache[$PolicyId]
    }

    $policy = Invoke-MgGraphRequest -Method GET -Uri "$script:GraphBase/deviceManagement/configurationPolicies/$($PolicyId)?`$select=id,name,priorityMetaData,settingCount" -OutputType PSObject
    $settings = @(Get-GraphCollection -Uri "$script:GraphBase/deviceManagement/configurationPolicies/$PolicyId/settings?`$expand=settingDefinitions")

    $definitions = @{}
    foreach ($setting in $settings) {
        foreach ($definition in $setting.settingDefinitions) {
            $definitions[$definition.id] = $definition
        }
    }

    $byId = @{}
    $byName = @{}
    foreach ($setting in $settings) {
        foreach ($value in (ConvertFrom-SettingInstance -Instance $setting.settingInstance -Definitions $definitions)) {
            if ($byId.ContainsKey($value.SettingDefinitionId)) {
                # Repeated inside a group collection: several values for one setting, so don't compare it.
                $existing = $byId[$value.SettingDefinitionId]
                $existing.ConfiguredValue = "$($existing.ConfiguredValue); $($value.ConfiguredValue)"
                $existing.Comparable = $false
                continue
            }
            $byId[$value.SettingDefinitionId] = $value
            if ($value.DisplayName -and -not $byName.ContainsKey($value.DisplayName)) {
                $byName[$value.DisplayName] = $value
            }
        }
    }

    $priority = $null
    if ($policy.priorityMetaData) { $priority = $policy.priorityMetaData.priority }

    $detail = [PSCustomObject]@{
        Priority     = $priority
        SettingCount = $policy.settingCount
        ById         = $byId
        ByName       = $byName
    }
    $script:SettingsCatalogCache[$PolicyId] = $detail
    return $detail
}

Function Get-IntuneRSOPData {
    param (
        [Parameter(Mandatory = $true)]
        [string]$DeviceName,
        # Writes the comparable settings to a JSON file for Test-IntuneRSOPOnDevice.ps1.
        [string]$ExportExpectedState
    )

    $device = Get-IntuneDeviceByName -DeviceName $DeviceName
    $policies = @(Get-IntuneConfigurationPolicyForDevice -DeviceID $device.id)

    $settings = foreach ($policy in $policies) {
        $detail = $null
        if ($policy.PolicyBaseTypeName -eq 'DeviceManagementConfigurationPolicy') {
            $detail = Get-IntuneSettingsCatalogPolicyDetail -PolicyId $policy.PolicyId
        }

        $statusRows = Get-IntunePolicySettingStatus -DeviceID $device.id -PolicyId $policy.PolicyId -UserID $policy.UserId -PolicyBaseTypeName $policy.PolicyBaseTypeName
        foreach ($row in $statusRows) {
            # Match the report row to the policy's own copy of the setting: by definition ID, then by name.
            $catalogSetting = $null
            if ($detail) {
                if ($row.SettingId -and $detail.ById.ContainsKey([string]$row.SettingId)) {
                    $catalogSetting = $detail.ById[[string]$row.SettingId]
                }
                elseif ($row.SettingName -and $detail.ByName.ContainsKey([string]$row.SettingName)) {
                    $catalogSetting = $detail.ByName[[string]$row.SettingName]
                }
            }

            $settingData = [PSCustomObject]@{
                DeviceName          = $device.deviceName
                PolicyName          = $policy.PolicyName
                PolicyType          = $policy.PolicyBaseTypeName
                PolicyPriority      = $null
                SettingName         = $row.SettingName
                SettingStatus       = Get-ReportValue -Row $row -Column 'SettingStatus'
                ErrorCode           = $row.ErrorCode
                ConfiguredValue     = $null
                ExpectedDeviceValue = $null
                Comparable          = $false
                CspPath             = $null
            }
            if ($detail) {
                $settingData.PolicyPriority = $detail.Priority
            }
            if ($catalogSetting) {
                $settingData.ConfiguredValue = $catalogSetting.ConfiguredValue
                $settingData.ExpectedDeviceValue = $catalogSetting.ExpectedDeviceValue
                $settingData.Comparable = $catalogSetting.Comparable
                $settingData.CspPath = $catalogSetting.CspPath
            }
            $settingData
        }
    }

    if ($ExportExpectedState) {
        $expected = @($settings | Where-Object { $_.Comparable -and $_.CspPath } |
            Select-Object PolicyName, SettingName, CspPath, ExpectedDeviceValue)
        ConvertTo-Json -InputObject $expected -Depth 3 | Set-Content -Path $ExportExpectedState -Encoding UTF8
        Write-Host "Wrote $($expected.Count) settings to $ExportExpectedState"
    }

    $settings
}
