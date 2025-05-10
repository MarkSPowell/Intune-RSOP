<#
.SYNOPSIS
Checks Intune policy and app assignments for users, groups, and devices.

.DESCRIPTION
This script helps IT administrators analyze and audit Intune assignments b helping to find the specific
Intune Policy causing an issue with a specific computer

#>

Import-Module Microsoft.Graph.Beta.Reports

#Connect-MgGraph -ClientId $ClientId -TenantId $TenantId

function Get-IntuneDeviceByName {
    param (
        [Parameter(Mandatory = $true)]
        [string]$DeviceName
    )
    $device = Get-MgDeviceManagementManagedDevice -Filter "deviceName eq '$DeviceName'" -Top 1
    if ($device) {
        return $device
    }
    else {
        Write-Host "Device not found."
    }
}

Function Get-IntuneConfigurationPolicyForDevice {
    param (
        [Parameter(Mandatory = $true)]
        [string]$DeviceID
    )

    $params = @{
        select  = @(
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
        filter  = "((PolicyBaseTypeName eq 'Microsoft.Management.Services.Api.DeviceConfiguration') or (PolicyBaseTypeName eq 'DeviceManagementConfigurationPolicy') or (PolicyBaseTypeName eq 'DeviceConfigurationAdmxPolicy') or (PolicyBaseTypeName eq 'Microsoft.Management.Services.Api.DeviceManagementIntent')) and (IntuneDeviceId eq '$($DeviceID)')"
        skip    = 0
        top     = 50
        orderBy = @(
            "PolicyName"
        )
    }

    Get-MgBetaDeviceManagementReportConfigurationPolicyReportForDevice -BodyParameter $params -Outfile C:\Temp\IntuneConfigurationPolicyForDevice.csv
    #This is not the CSV I was expecting...
    $reportConfigurationJson = Get-Content "C:\Temp\IntuneConfigurationPolicyForDevice.csv" | ConvertFrom-Json
    #My apologies, this can't be the best way to do this...
    $policyArray = @()
    $reportConfigurationJson.Values | ForEach-Object {
        $PolicyData = [PSCustomObject]@{
            IntuneDeviceId            = $_[0]
            PolicyBaseTypeName        = $_[1]
            PolicyID                  = $_[2]
            PolicyName                = $_[3]
            PolicyStatus              = $_[4]
            PspdpuLastModifiedTimeUtc = $_[5]
            #One of these two is probably UnifiedPolicyType
            SomeOtherPolicyTypeName   = $_[6]
            SomeThirdPolicyTypeName   = $_[7]
            UPN                       = $_[8]
            UserId                    = $_[9]

            DeviceID                  = $DeviceID
        };
        $policyArray += $PolicyData
    }


    return $policyArray
}



Function Get-GroupPolicySettingDeviceSettingReport {
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

    $params = @{
        top     = 50
        skip    = 0
        select  = @(
            "SettingName"
            "SettingStatus"
            "ErrorCode"
            "SettingId"
            "SettingInstanceId"
        )
        orderBy = @(
        )
        search  = ""
        filter  = "(PolicyId eq '$PolicyId') and (DeviceId eq '$DeviceID') and (UserId eq '$UserID')"
    }



    switch ($PolicyBaseTypeName) {
        "Microsoft.Management.Services.Api.DeviceConfiguration" {
            $params = @{
                select  = @(
                    "SettingName"
                    "SettingStatus"
                    "ErrorCode"
                    "SettingInstanceId"
                    "SettingInstancePath"
                )
                skip    = 0
                top     = 50
                filter  = "(PolicyId eq '$PolicyId') and (DeviceId eq '$DeviceID') and (UserId eq '$UserID')"
                orderBy = @(
                )
            }
            Get-MgBetaDeviceManagementReportConfigurationSettingNonComplianceReport -BodyParameter $params -OutFile C:\Temp\DeviceConfigurationSettingReport-$PolicyID.csv
            $ReportConfigurationSettingReportJson = Get-Content "C:\Temp\DeviceConfigurationSettingReport-$PolicyID.csv" | ConvertFrom-Json
            #My apologies, this can't be the best way to do this... again
            $policyArray = @()
            $ReportConfigurationSettingReportJson.Values | ForEach-Object {
                $PolicyData = [PSCustomObject]@{
                    ErrorCode           = $_[0]
                    SettingInstanceId   = $_[1]
                    SettingInstancePath = $_[2]
                    SettingName         = $_[3]
                    SettingStatus       = $_[4]
                    DeviceID            = $DeviceID
                    PolicyID            = $PolicyID
                };
                $policyArray += $PolicyData
            }

        }
        "DeviceManagementConfigurationPolicy" {
            $params = @{
                top     = 50
                skip    = 0
                select  = @(
                    "SettingName"
                    "SettingStatus"
                    "ErrorCode"
                    "SettingId"
                    "SettingInstanceId"
                )
                orderBy = @(
                )
                search  = ""
                filter  = "(PolicyId eq '$PolicyId') and (DeviceId eq '$DeviceID') and (UserId eq '$UserID')"
            }
            Get-MgBetaDeviceManagementReportConfigurationSettingReport -BodyParameter $params -OutFile C:\Temp\GroupPolicySettingDeviceSettingReport-$PolicyID.csv
            $GroupPolicySettingDeviceSettingReportJson = Get-Content "C:\Temp\GroupPolicySettingDeviceSettingReport-$PolicyID.csv" | ConvertFrom-Json
            #My apologies, this can't be the best way to do this... again
            $policyArray = @()
            $GroupPolicySettingDeviceSettingReportJson.Values | ForEach-Object {
                $PolicyData = [PSCustomObject]@{
                    ErrorCode         = $_[0]
                    SettingID         = $_[1]
                    SettingId_loc     = $_[2]
                    SettingInstanceId = $_[3]
                    SettingStatus     = $_[4]
                    SettingName       = $_[5]
                    DeviceID          = $DeviceID
                    PolicyID          = $PolicyID
                };
                $policyArray += $PolicyData
            }


        } "DeviceConfigurationAdmxPolicy" {
            $params = @{
                top     = 50
                skip    = 0
                select  = @(
                    "SettingName"
                    "SettingStatus"
                    "ErrorCode"
                    "SettingId"
                    "SettingInstanceId"
                )
                orderBy = @(
                )
                search  = ""
                filter  = "(PolicyId eq '$PolicyId') and (DeviceId eq '$DeviceID') and (UserId eq '$UserID')"
            }
            Get-MgBetaDeviceManagementReportGroupPolicySettingDeviceSettingReport -BodyParameter $params -OutFile C:\Temp\GroupPolicySettingDeviceSettingReport-$PolicyID.csv

            $ReportConfigurationSettingReportJson = Get-Content "C:\Temp\GroupPolicySettingDeviceSettingReport-$PolicyID.csv" | ConvertFrom-Json
            #My apologies, this can't be the best way to do this... again
            $policyArray = @()
            $ReportConfigurationSettingReportJson.Values | ForEach-Object {
                $PolicyData = [PSCustomObject]@{
                    ErrorCode         = $_[0]
                    SettingID         = $_[1]
                    SettingInstanceId = $_[2]
                    SettingName       = $_[3]
                    SettingStatus     = $_[4]
                    DeviceID          = $DeviceID
                    PolicyID          = $PolicyID
                };
                $policyArray += $PolicyData
            }
        } "Microsoft.Management.Services.Api.DeviceManagementIntent" {
            #Todo
            #I don't have any of these in my environment, so I'm not sure what the API call is yet
        }
    }
    #This is also not the CSV I was expecting...

    return $policyArray
}

Function Get-IntuneRSOPData {
    param (
        [Parameter(Mandatory = $true)]
        [string]$DeviceName
    )
    $device = Get-IntuneDeviceByName -DeviceName $DeviceName
    $deviceID = $device.id
    $deviceConfigurationPolicies = Get-IntuneConfigurationPolicyForDevice -DeviceID $deviceID
    $settings = @()
    $deviceConfigurationPolicies | ForEach-Object {
        $DeviceSettingsReport = Get-GroupPolicySettingDeviceSettingReport -DeviceID $deviceID -PolicyID $_.PolicyID -UserID $_.UserID -PolicyBaseTypeName $_.PolicyBaseTypeName
        $PolicyName = $_.PolicyName
        $DeviceSettingsReport | ForEach-Object {
            $SettingsData = [PSCustomObject]@{
                SettingName   = $_.SettingName
                PolicyName    = $PolicyName
                SettingStatus = $_.SettingStatus
            }
            $settings += $SettingsData
        }
    }
    $settings += $SettingsData

    $settings | Out-GridView
}
