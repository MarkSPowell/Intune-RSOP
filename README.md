# Intune-RSOP
Resultant Set of Policy (RSOP) for Microsoft Intune: a PowerShell script that lists every Intune setting applied to a Windows device, which policy sets it, and whether it really took effect on the endpoint.

Group Policy has `gpresult`. Intune doesn't. When a setting misbehaves on one computer, this answers "which Intune policy is doing this?" without clicking through every profile in the admin center.

A practice script to implement what I learned at MMSMOA2025. Comes with a 100% Worked on My Machine Guarantee. Open to suggestions on how I have make this easier for other people to run- Usually I'm just sharing these with my future self. 

## What it does

`Get-IntuneRSOP.ps1` uses the Microsoft Graph API to list every configuration setting Intune reports for a device, the policy that sets it, and whether it applied (succeeded, error or conflict). It covers Settings Catalog policies, device configuration profiles, Administrative Templates (ADMX) and endpoint security policies. For Settings Catalog policies it also shows the configured value, the policy priority, and the CSP path the setting writes to on the device.

`Test-IntuneRSOPOnDevice.ps1` runs on the endpoint and checks those settings are actually in effect, by comparing them with the MDM policy values Windows records in the registry (PolicyManager). It can also run as an Intune Remediations detection script.

## Why

- Find which Intune policy is causing an issue on a specific device
- Troubleshoot Intune policy conflicts and settings that show "Succeeded" but don't seem to work
- Audit the effective Intune configuration of a device, like `gpresult /h` for MDM

## Requirements

- The `Microsoft.Graph.Authentication` module (`Install-Module Microsoft.Graph.Authentication`). No other Graph modules are needed.
- Graph permissions: `DeviceManagementConfiguration.Read.All` and `DeviceManagementManagedDevices.Read.All`.

## Usage

```powershell
. .\Get-IntuneRSOP.ps1
Connect-MgGraph -Scopes DeviceManagementConfiguration.Read.All, DeviceManagementManagedDevices.Read.All
Get-IntuneRSOPData -DeviceName PC-0042 | Out-GridView
```

### Checking the device

Export what the device should hold, then run the check on the device:

```powershell
Get-IntuneRSOPData -DeviceName PC-0042 -ExportExpectedState C:\Temp\PC-0042-expected.json
```

```powershell
# On PC-0042
.\Test-IntuneRSOPOnDevice.ps1 -ExpectedStatePath C:\Temp\PC-0042-expected.json | Out-GridView
```

Each setting comes back as `Applied`, `Different`, `Missing`, `Present` (ADMX-backed, can't compare values) or `NotChecked`.

To run it without touching the device, paste the exported JSON into `$EmbeddedExpectedState` in `Test-IntuneRSOPOnDevice.ps1` and upload it as a Remediations detection script. Then trigger it with `POST /beta/deviceManagement/managedDevices/{id}/initiateOnDemandProactiveRemediation` and read the one-line result from `managedDevices/{id}/deviceHealthScriptStates` (`preRemediationDetectionScriptOutput`). That needs Remediations licensing and the `DeviceManagementManagedDevices.PrivilegedOperations.All` permission.

## Limits

- Only Settings Catalog policies can be checked on the device. Graph gives no CSP path for old-style device configuration profiles or ADMX template policies.
- The device check only reads Policy CSP settings (`./Vendor/MSFT/Policy/Config/...`). BitLocker, Firewall, the Defender CSP and similar keep their state elsewhere and show as `NotChecked`.
- Security baselines and endpoint security policies still on the older "intent" format use `getDeviceManagementIntentSettingsReport`, which is undocumented and untested here.
- Report status only updates when the device checks in.
