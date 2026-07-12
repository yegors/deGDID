#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Lab-only: hunt LID rehydrate sources / registry audit. Not needed for normal Protect/Wipe.
  Prefer ..\degdid.ps1 for end-user actions.
#>
[CmdletBinding()]
param(
  [ValidateSet('Map', 'AuditOn', 'AuditOff', 'WipeWatch', 'AuditRead', 'DeepSearch')]
  [string]$Phase = 'Map',
  [string]$KnownLid = '',
  [string]$TargetSid = '',
  [switch]$ShowIdentifier
)

$ErrorActionPreference = 'Continue'
$auditStateDir = Join-Path $env:ProgramData 'degdid'
$auditStatePath = Join-Path $auditStateDir 'lid-audit-state.json'

function Get-ResearchTarget {
  param([string]$RequestedSid)

  $sid = $RequestedSid
  if (-not $sid) {
    $computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if (-not $computer.UserName) {
      throw 'No active interactive user was reported; pass -TargetSid explicitly.'
    }
    $account = [System.Security.Principal.NTAccount]::new(
      [string]$computer.UserName
    )
    $sid = $account.Translate(
      [System.Security.Principal.SecurityIdentifier]
    ).Value
  }
  if ($sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') {
    throw 'TargetSid must be a human-profile SID.'
  }

  $profileKey = (
    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{0}' -f
    $sid
  )
  $profilePath = (
    Get-ItemProperty -LiteralPath $profileKey -ErrorAction Stop
  ).ProfileImagePath
  $profilePath = [Environment]::ExpandEnvironmentVariables([string]$profilePath)
  $hivePath = 'Registry::HKEY_USERS\{0}' -f $sid
  if (-not (Test-Path -LiteralPath $hivePath -ErrorAction Stop)) {
    throw 'Target user hive is not loaded.'
  }

  return [pscustomobject]@{
    Sid = $sid
    ProfilePath = $profilePath
    HivePath = $hivePath
    RegistryNativePath = (
      '{0}\SOFTWARE\Microsoft\IdentityCRL\ExtendedProperties' -f $sid
    )
  }
}

if (
  $Phase -eq 'AuditOff' -and
  -not $TargetSid -and
  (Test-Path -LiteralPath $auditStatePath)
) {
  $savedAuditState = Get-Content -LiteralPath $auditStatePath -Raw -ErrorAction Stop |
    ConvertFrom-Json
  $TargetSid = [string]$savedAuditState.TargetSid
}

$researchTarget = Get-ResearchTarget -RequestedSid $TargetSid
$targetLocalAppData = Join-Path $researchTarget.ProfilePath 'AppData\Local'
$extPath = $researchTarget.HivePath + '\SOFTWARE\Microsoft\IdentityCRL\ExtendedProperties'
$extNative = $researchTarget.RegistryNativePath
$userLocal = Join-Path $targetLocalAppData 'Microsoft'
$userRoaming = Join-Path $researchTarget.ProfilePath 'AppData\Roaming\Microsoft'

function Get-ShortHash([string]$value) {
  if (-not $value) { return '-' }
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($value)
    return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '').Substring(0, 8)
  } finally {
    $sha.Dispose()
  }
}

function Format-Identifier([string]$value) {
  if (-not $value) { return '(none)' }
  if ($ShowIdentifier) { return $value }
  $prefix = if ($value.Length -ge 4) { $value.Substring(0, 4) } else { '<id>' }
  return '{0}...#{1}' -f $prefix, (Get-ShortHash $value)
}

function Format-ResearchText([string]$value) {
  if ($ShowIdentifier -or -not $value) { return $value }
  $result = $value
  $result = [regex]::Replace(
    $result,
    '(?i)(?<![0-9a-f])0018[0-9a-f]{12}(?![0-9a-f])',
    '<puid>'
  )
  $result = [regex]::Replace(
    $result,
    '(?i)S-1-5-21-\d+-\d+-\d+-\d+',
    '<sid>'
  )
  if ($researchTarget.ProfilePath) {
    $result = [regex]::Replace(
      $result,
      [regex]::Escape($researchTarget.ProfilePath),
      '<profile>',
      [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
  }
  return $result
}

function Get-CurrentLid {
  if (-not (Test-Path $extPath)) { return $null }
  return (Get-ItemProperty $extPath -EA SilentlyContinue).LID
}

function Format-RedactedValue([string]$name, $v) {
  if ($null -eq $v) { return $null }
  if ($v -is [byte[]]) { return "bytes[$($v.Length)]" }
  $s = "$v"
  if ($name -match '^(LID|DeviceId)$') {
    return Format-Identifier $s
  }
  if ($name -match 'Ticket|Token|Secret|Password|Key|Blob|Credential') {
    return "REDACTED(len=$($s.Length))"
  }
  if ($s.Length -gt 160) { return $s.Substring(0, 160) + '...' }
  return $s
}

function Write-PropertyDump([string]$path, [string]$label) {
  if (-not (Test-Path $path)) {
    Write-Output "$label MISSING"
    return
  }
  Write-Output $label
  $p = Get-ItemProperty $path -EA SilentlyContinue
  $p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
    $displayName = if ($_.Name -match '^(?i)0018[0-9a-f]{12}$') {
      Format-Identifier $_.Name
    } else {
      $_.Name
    }
    Write-Output ("  {0}={1}" -f $displayName, (Format-RedactedValue $_.Name $_.Value))
  }
}

function Get-RegistryAuditPolicy {
  $output = @(& auditpol /get /subcategory:"Registry" 2>&1)
  if ($LASTEXITCODE -ne 0) {
    throw "auditpol query failed with exit code $LASTEXITCODE"
  }
  $text = $output -join "`n"
  if ($text -notmatch '(?i)\b(No Auditing|Success|Failure)\b') {
    throw 'Registry audit policy output could not be parsed.'
  }
  return [pscustomobject]@{
    Success = $text -match '(?i)\bSuccess\b'
    Failure = $text -match '(?i)\bFailure\b'
  }
}

function Set-RegistryAuditPolicy {
  param(
    [bool]$Success,
    [bool]$Failure
  )
  $successMode = if ($Success) { 'enable' } else { 'disable' }
  $failureMode = if ($Failure) { 'enable' } else { 'disable' }
  & auditpol @(
    '/set',
    '/subcategory:Registry',
    "/success:$successMode",
    "/failure:$failureMode"
  ) | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "auditpol update failed with exit code $LASTEXITCODE"
  }
}

function Enable-LidAudit {
  if (Test-Path -LiteralPath $auditStatePath) {
    throw "Audit state already exists at $auditStatePath. Run -Phase AuditOff first."
  }
  New-Item -ItemType Directory -Path $auditStateDir -Force | Out-Null
  $userKey = [Microsoft.Win32.Registry]::Users.OpenSubKey($extNative, $true)
  if (-not $userKey) {
    New-Item -Path $extPath -Force | Out-Null
    $userKey = [Microsoft.Win32.Registry]::Users.OpenSubKey($extNative, $true)
  }
  if (-not $userKey) {
    throw 'IdentityCRL ExtendedProperties could not be opened for audit setup.'
  }
  $acl = $userKey.GetAccessControl(
    [System.Security.AccessControl.AccessControlSections]::Audit
  )
  $previousSddl = $acl.GetSecurityDescriptorSddlForm(
    [System.Security.AccessControl.AccessControlSections]::Audit
  )
  $userKey.Close()

  $previousPolicy = Get-RegistryAuditPolicy
  [pscustomobject]@{
    TargetSid = $researchTarget.Sid
    RegistryPath = $extNative
    PreviousSddl = $previousSddl
    PreviousAuditSuccess = $previousPolicy.Success
    PreviousAuditFailure = $previousPolicy.Failure
    CreatedAt = (Get-Date).ToString('o')
  } | ConvertTo-Json | Set-Content -LiteralPath $auditStatePath -Encoding UTF8

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
  try {
    Set-RegistryAuditPolicy -Success $true -Failure $true
    $userKey = [Microsoft.Win32.Registry]::Users.OpenSubKey($extNative, $true)
    if (-not $userKey) {
      throw 'IdentityCRL ExtendedProperties could not be reopened for audit setup.'
    }
    $acl = $userKey.GetAccessControl(
      [System.Security.AccessControl.AccessControlSections]::Audit
    )
    $acl.SetAuditRule($rule)
    $userKey.SetAccessControl($acl)
    $userKey.Close()
  } catch {
    if ($userKey) {
      $userKey.Close()
    }
    try {
      Disable-LidAudit | Out-Null
    } catch {
      Write-Warning "Automatic audit rollback failed: $($_.Exception.Message)"
    }
    throw
  }
  Write-Output 'Audit SACL enabled; prior SACL and audit policy were saved for AuditOff.'
}

function Disable-LidAudit {
  if (-not (Test-Path -LiteralPath $auditStatePath)) {
    Write-Output 'No saved lid-audit state exists; nothing to restore.'
    return
  }

  $state = Get-Content -LiteralPath $auditStatePath -Raw -ErrorAction Stop |
    ConvertFrom-Json
  $userKey = [Microsoft.Win32.Registry]::Users.OpenSubKey(
    [string]$state.RegistryPath,
    $true
  )
  if (-not $userKey) {
    throw 'IdentityCRL ExtendedProperties is unavailable; SACL was not restored.'
  }
  try {
    $acl = New-Object System.Security.AccessControl.RegistrySecurity
    $acl.SetSecurityDescriptorSddlForm(
      [string]$state.PreviousSddl,
      [System.Security.AccessControl.AccessControlSections]::Audit
    )
    $userKey.SetAccessControl($acl)
  } finally {
    $userKey.Close()
  }

  Set-RegistryAuditPolicy `
    -Success ([bool]$state.PreviousAuditSuccess) `
    -Failure ([bool]$state.PreviousAuditFailure)
  Remove-Item -LiteralPath $auditStatePath -Force -ErrorAction Stop
  Write-Output 'Prior registry SACL and audit policy restored.'
}

switch ($Phase) {
  'Map' {
    $lid = Get-CurrentLid
    Write-Output "CurrentLIDPrefix=$(if ($lid) { $lid.Substring(0, [Math]::Min(4, $lid.Length)) } else { '-' })"
    $propertyPath = $researchTarget.HivePath + '\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Property'
    $tokenPath = $researchTarget.HivePath + '\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Token'
    Write-PropertyDump $extPath 'Target-user ExtendedProperties'
    Write-PropertyDump $propertyPath 'Target-user Immersive Property'
    Get-ChildItem $tokenPath -EA SilentlyContinue | ForEach-Object {
      Write-PropertyDump $_.PSPath ("Token\$($_.PSChildName)")
    }
    foreach ($p in @(
      'Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\IdentityCRL\ExtendedProperties',
      'Registry::HKEY_USERS\S-1-5-18\Software\Microsoft\IdentityCRL\ExtendedProperties'
    )) { Write-PropertyDump $p $p }

    Write-Output '=== candidate dirs (names/sizes) ==='
    $dirs = @(
      'C:\ProgramData\Microsoft\IdentityCRL',
      (Join-Path $userLocal 'IdentityCRL'),
      (Join-Path $userLocal 'TokenBroker'),
      (Join-Path $userLocal 'OneAuth'),
      (Join-Path $userLocal 'Windows\CloudStore'),
      (Join-Path $targetLocalAppData 'ConnectedDevicesPlatform')
    )
    foreach ($d in $dirs) {
      if (-not (Test-Path $d)) {
        Write-Output ("MISS {0}" -f (Format-ResearchText $d))
        continue
      }
      Write-Output ("DIR {0}" -f (Format-ResearchText $d))
      Get-ChildItem $d -Recurse -Force -EA SilentlyContinue | Select-Object -First 40 | ForEach-Object {
        Write-Output ("  {0} len={1}" -f (Format-ResearchText $_.FullName), $_.Length)
      }
    }
  }
  'AuditOn' { Enable-LidAudit }
  'AuditOff' { Disable-LidAudit }
  'WipeWatch' {
    Enable-LidAudit
    Write-Output "BeforeWipeHasLid=$([bool](Get-CurrentLid))"
    & (Join-Path $PSScriptRoot '..\degdid.ps1') -Wipe
    if ($LASTEXITCODE -ne 0) {
      Write-Error "Wipe failed with exit code $LASTEXITCODE. Run -Phase AuditOff."
      break
    }
    Write-Output "AfterWipeHasLid=$([bool](Get-CurrentLid))"
    Write-Output 'REBOOT, then: -Phase AuditRead, followed by -Phase AuditOff'
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
          } | ForEach-Object { Write-Output (Format-ResearchText $_) }
        }
    } catch {
      Write-Output ("No 4657 / access denied: {0}" -f $_.Exception.Message)
    }
    Write-Output 'When finished reading, run: -Phase AuditOff'
  }
  'DeepSearch' {
    $lid = if ($KnownLid) { $KnownLid } else { Get-CurrentLid }
    if (-not $lid) { Write-Error 'No LID to search for'; exit 1 }
    if ($lid -notmatch '^[0-9A-Fa-f]{16}$') {
      Write-Error 'KnownLid must be exactly 16 hexadecimal characters'
      exit 1
    }
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
              Write-Output (
                "HIT {0} len={1}" -f
                (Format-ResearchText $_.FullName),
                $_.Length
              )
              $hits++
            }
          } catch {
            Write-Verbose ("Skipped unreadable file: {0}" -f $_.Exception.Message)
          }
        }
    }
    Write-Output "Done hits=$hits"
  }
}
