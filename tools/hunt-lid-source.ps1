#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Lab-only: hunt LID rehydrate sources / registry audit. Not needed for normal Protect/Wipe.
  Prefer ..\degdid.ps1 for end-user actions.
#>
[CmdletBinding()]
param(
  [ValidateSet('Map', 'AuditOn', 'WipeWatch', 'AuditRead', 'DeepSearch')]
  [string]$Phase = 'Map',
  [string]$KnownLid = ''
)

$ErrorActionPreference = 'Continue'
$extPath = 'HKCU:\SOFTWARE\Microsoft\IdentityCRL\ExtendedProperties'
$extNative = 'SOFTWARE\Microsoft\IdentityCRL\ExtendedProperties'
$userLocal = Join-Path $env:LOCALAPPDATA 'Microsoft'
$userRoaming = Join-Path $env:APPDATA 'Microsoft'

function Get-CurrentLid {
  if (-not (Test-Path $extPath)) { return $null }
  return (Get-ItemProperty $extPath -EA SilentlyContinue).LID
}

function Redact-Val([string]$name, $v) {
  if ($null -eq $v) { return $null }
  if ($v -is [byte[]]) { return "bytes[$($v.Length)]" }
  $s = "$v"
  if ($name -match 'Ticket|Token|Secret|Password|Key|Blob|Credential') {
    return "REDACTED(len=$($s.Length))"
  }
  if ($s.Length -gt 160) { return $s.Substring(0, 160) + '...' }
  return $s
}

function Dump-Props([string]$path, [string]$label) {
  if (-not (Test-Path $path)) {
    Write-Output "$label MISSING"
    return
  }
  Write-Output $label
  $p = Get-ItemProperty $path -EA SilentlyContinue
  $p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
    Write-Output ("  {0}={1}" -f $_.Name, (Redact-Val $_.Name $_.Value))
  }
}

function Enable-LidAudit {
  auditpol /set /subcategory:"Registry" /success:enable /failure:enable | Out-Null
  $userKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($extNative, $true)
  if (-not $userKey) {
    New-Item -Path $extPath -Force | Out-Null
    $userKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($extNative, $true)
  }
  $acl = $userKey.GetAccessControl()
  $rights = [System.Security.AccessControl.RegistryRights](
    [int][System.Security.AccessControl.RegistryRights]::SetValue -bor
    [int][System.Security.AccessControl.RegistryRights]::CreateSubKey -bor
    [int][System.Security.AccessControl.RegistryRights]::Delete -bor
    [int][System.Security.AccessControl.RegistryRights]::WriteKey
  )
  $rule = New-Object System.Security.AccessControl.RegistryAuditRule(
    'Everyone', $rights,
    [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AuditFlags]::Success
  )
  $acl.SetAuditRule($rule)
  $userKey.SetAccessControl($acl)
  $userKey.Close()
  Write-Output 'Audit SACL set on HKCU IdentityCRL\ExtendedProperties.'
}

switch ($Phase) {
  'Map' {
    $lid = Get-CurrentLid
    Write-Output "CurrentLIDPrefix=$(if ($lid) { $lid.Substring(0, [Math]::Min(4, $lid.Length)) } else { '-' })"
    Dump-Props $extPath 'HKCU ExtendedProperties'
    Dump-Props 'HKCU:\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Property' 'HKCU Immersive Property'
    Get-ChildItem 'HKCU:\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Token' -EA SilentlyContinue | ForEach-Object {
      Dump-Props $_.PSPath ("Token\$($_.PSChildName)")
    }
    foreach ($p in @(
      'Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\IdentityCRL\ExtendedProperties',
      'Registry::HKEY_USERS\S-1-5-18\Software\Microsoft\IdentityCRL\ExtendedProperties'
    )) { Dump-Props $p $p }

    Write-Output '=== candidate dirs (names/sizes) ==='
    $dirs = @(
      'C:\ProgramData\Microsoft\IdentityCRL',
      (Join-Path $userLocal 'IdentityCRL'),
      (Join-Path $userLocal 'TokenBroker'),
      (Join-Path $userLocal 'OneAuth'),
      (Join-Path $userLocal 'Windows\CloudStore'),
      (Join-Path $env:LOCALAPPDATA 'ConnectedDevicesPlatform')
    )
    foreach ($d in $dirs) {
      if (-not (Test-Path $d)) { Write-Output "MISS $d"; continue }
      Write-Output "DIR $d"
      Get-ChildItem $d -Recurse -Force -EA SilentlyContinue | Select-Object -First 40 | ForEach-Object {
        Write-Output ("  {0} len={1}" -f $_.FullName, $_.Length)
      }
    }
  }
  'AuditOn' { Enable-LidAudit }
  'WipeWatch' {
    Enable-LidAudit
    Write-Output "BeforeWipeHasLid=$([bool](Get-CurrentLid))"
    & (Join-Path $PSScriptRoot '..\degdid.ps1') -Wipe
    Write-Output "AfterWipeHasLid=$([bool](Get-CurrentLid))"
    Write-Output 'REBOOT, then: -Phase AuditRead'
  }
  'AuditRead' {
    Write-Output "CurrentHasLid=$([bool](Get-CurrentLid))"
    try {
      Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4657 } -MaxEvents 200 -EA Stop |
        Where-Object { $_.Message -match 'IdentityCRL|ExtendedProperties|LID' } |
        Select-Object -First 50 | ForEach-Object {
          Write-Output ("--- {0:o} ---" -f $_.TimeCreated)
          ($_.Message -split "`r?`n") | Where-Object {
            $_ -match 'Account Name|Process Name|Process ID|Object Name|Object Value Name|Operation'
          } | ForEach-Object { Write-Output $_ }
        }
    } catch {
      Write-Output ("No 4657 / access denied: {0}" -f $_.Exception.Message)
    }
  }
  'DeepSearch' {
    $lid = if ($KnownLid) { $KnownLid } else { Get-CurrentLid }
    if (-not $lid) { Write-Error 'No LID to search for'; exit 1 }
    $dec = [Convert]::ToUInt64($lid, 16).ToString()
    Write-Output "Searching for LID prefix $($lid.Substring(0,4))... / decimal (not printed)"
    $roots = @(
      $userLocal, $userRoaming,
      'C:\ProgramData\Microsoft',
      'C:\Windows\ServiceProfiles',
      'C:\Windows\System32\config\systemprofile\AppData'
    )
    $hits = 0
    foreach ($root in $roots) {
      if (-not (Test-Path $root)) { continue }
      Get-ChildItem $root -Recurse -Force -File -EA SilentlyContinue |
        Where-Object { $_.Length -lt 8MB -and $_.Length -gt 0 } |
        ForEach-Object {
          try {
            $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
            $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
            $utf16 = [System.Text.Encoding]::Unicode.GetString($bytes)
            if ($ascii.Contains($lid) -or $ascii.Contains($dec) -or $utf16.Contains($lid) -or $utf16.Contains($dec)) {
              Write-Output ("HIT {0} len={1}" -f $_.FullName, $_.Length)
              $hits++
            }
          } catch {}
        }
    }
    Write-Output "Done hits=$hits"
  }
}
