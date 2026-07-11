#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Check, wipe, decoy, and/or block Microsoft GDID (Global Device Identifier / Device PUID).

.DESCRIPTION
  Public entry point for degdid. Run elevated PowerShell.

  Recommended for a contaminated PC that should stop carrying a live install id:
    .\degdid.ps1 -Protect

  That applies registration blocks FIRST, then performs an expanded local wipe
  (LID + Immersive Property rehydrate blobs + device tickets + related caches).

.PARAMETER Status
  Show whether a GDID/LID is present and whether registration blocks are active.

.PARAMETER Wipe
  Delete local GDID copies (expanded wipe). Prefer -Protect instead of Wipe alone while online.

.PARAMETER Decoy
  Write a random local 0018-shaped LID (not server-issued). Prefer with -Protect / -Block.

.PARAMETER Block
  Block DeviceAdd / DDS / activity registration hosts (hosts file + outbound firewall IPs).

.PARAMETER Unblock
  Remove degdid hosts marker and firewall rules.

.PARAMETER Protect
  Block, then Wipe (default) or Decoy if -UseDecoy is also set. Preferred one-shot.

.PARAMETER DryRun
  Print actions without changing the system.

.NOTES
  Limits: does not erase Microsoft server-side history of an old GDID; does not stop
  all telemetry; breaks MSA / Store sign-in / Phone Link style features that need
  the blocked endpoints. Windows Update is intended to keep working.
  Lab evidence: docs/experiments/ (Win11 25H2).
#>
[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
  [Parameter(ParameterSetName = 'Status')]
  [switch]$Status,

  [Parameter(ParameterSetName = 'Wipe')]
  [switch]$Wipe,

  [Parameter(ParameterSetName = 'Decoy')]
  [switch]$Decoy,

  [Parameter(ParameterSetName = 'Block')]
  [switch]$Block,

  [Parameter(ParameterSetName = 'Unblock')]
  [switch]$Unblock,

  [Parameter(ParameterSetName = 'Protect')]
  [switch]$Protect,

  [Parameter(ParameterSetName = 'Protect')]
  [switch]$UseDecoy,

  [switch]$DryRun
)

$ErrorActionPreference = 'Continue'

# Default to Status when no action switch is set
if (-not ($Status -or $Wipe -or $Decoy -or $Block -or $Unblock -or $Protect)) {
  $Status = $true
}

$MarkerBegin = '# BEGIN degdid-registration-block'
$MarkerEnd   = '# END degdid-registration-block'
$HostsPath   = "$env:SystemRoot\System32\drivers\etc\hosts"
$RulePrefix  = 'degdid-block-'

$BlockHosts = @(
  'login.live.com',
  'account.live.com',
  'cs.dds.microsoft.com',
  'dds.microsoft.com',
  'aad.cs.dds.microsoft.com',
  'fd.dds.microsoft.com',
  'cdpcs.access.microsoft.com',
  'ztd.dds.microsoft.com',
  'activity.windows.com',
  'assets.activity.windows.com',
  'edge.activity.windows.com'
)

$LidPaths = @(
  'HKCU:\SOFTWARE\Microsoft\IdentityCRL\ExtendedProperties',
  'Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\IdentityCRL\ExtendedProperties',
  'Registry::HKEY_USERS\S-1-5-18\Software\Microsoft\IdentityCRL\ExtendedProperties'
)

function Test-LooksOnline {
  $nics = @(Get-NetAdapter -EA SilentlyContinue | Where-Object { $_.Status -eq 'Up' })
  if (-not $nics) { return $false }
  $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -EA SilentlyContinue |
    Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' })
  return [bool]$routes
}

function ConvertTo-Gdid([string]$lid) {
  if (-not $lid) { return $null }
  try { return "g:$([Convert]::ToUInt64($lid, 16))" } catch { return $null }
}

function Get-LidAt([string]$Path) {
  if (-not (Test-Path $Path)) { return $null }
  try { return (Get-ItemProperty -Path $Path -EA Stop).LID } catch { return $null }
}

function Ensure-Key([string]$Path) {
  if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
}

function Test-HostsBlockPresent {
  if (-not (Test-Path $HostsPath)) { return $false }
  return ((Get-Content $HostsPath -EA SilentlyContinue) -contains $MarkerBegin)
}

function Get-ImmersivePropertyCount {
  $prop = 'HKCU:\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Property'
  if (-not (Test-Path $prop)) { return 0 }
  $pp = Get-ItemProperty $prop -EA SilentlyContinue
  return @($pp.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }).Count
}

function New-DecoyLid {
  $bytes = New-Object byte[] 6
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  $hex = ($bytes | ForEach-Object { $_.ToString('X2') }) -join ''
  return '0018' + $hex
}

function Clear-ImmersiveProperty {
  $prop = 'HKCU:\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Property'
  if (-not (Test-Path $prop)) { return }
  $pp = Get-ItemProperty $prop -EA SilentlyContinue
  foreach ($n in @($pp.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
    if ($DryRun) { Write-Output "DryRun clear Immersive Property $($n.Name)"; continue }
    Remove-ItemProperty -Path $prop -Name $n.Name -EA SilentlyContinue
    Write-Output "Cleared Immersive Property $($n.Name.Substring(0, [Math]::Min(8, $n.Name.Length)))..."
  }
}

function Clear-TokenDeviceFields {
  param(
    [string]$NewDeviceId
  )
  $setId = $PSBoundParameters.ContainsKey('NewDeviceId')
  $tok = 'HKCU:\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Token'
  if (-not (Test-Path $tok)) { return }
  Get-ChildItem $tok -EA SilentlyContinue | ForEach-Object {
    if ($DryRun) {
      Write-Output "DryRun Token $($_.PSChildName)"
      return
    }
    Remove-ItemProperty -Path $_.PSPath -Name DeviceTicket -EA SilentlyContinue
    if ($setId) {
      New-ItemProperty -Path $_.PSPath -Name DeviceId -Value $NewDeviceId -PropertyType String -Force | Out-Null
      Write-Output "Set Token DeviceId $($_.PSChildName)"
    } else {
      Remove-ItemProperty -Path $_.PSPath -Name DeviceId -EA SilentlyContinue
      Write-Output "Cleared Token DeviceId/DeviceTicket $($_.PSChildName)"
    }
  }
}

function Clear-AuxCaches {
  if (-not $DryRun) {
    cmdkey /delete:'WindowsLive:target=virtualapp/didlogical' 2>$null | Out-Null
    Write-Output 'Removed cmdkey WindowsLive didlogical (if present)'
  } else {
    Write-Output 'DryRun cmdkey delete didlogical'
  }
  $tb = Join-Path $env:LOCALAPPDATA 'Microsoft\TokenBroker\Cache'
  if (Test-Path $tb) {
    if ($DryRun) { Write-Output "DryRun clear $tb" }
    else {
      Get-ChildItem $tb -Force -EA SilentlyContinue | Remove-Item -Force -EA SilentlyContinue
      Write-Output "Cleared TokenBroker cache"
    }
  }
  $cdp = Join-Path $env:LOCALAPPDATA 'ConnectedDevicesPlatform'
  if (Test-Path $cdp) {
    if ($DryRun) { Write-Output "DryRun clear $cdp" }
    else {
      Get-ChildItem $cdp -Force -EA SilentlyContinue | Remove-Item -Recurse -Force -EA SilentlyContinue
      Write-Output "Cleared ConnectedDevicesPlatform folder"
    }
  }
}

function Invoke-Wipe {
  Write-Output 'Wiping LID + Immersive Property + Token device fields + caches...'
  foreach ($p in $LidPaths) {
    if (-not (Test-Path $p)) { continue }
    if ($DryRun) { Write-Output "DryRun clear LID $p"; continue }
    Remove-ItemProperty -Path $p -Name LID -EA SilentlyContinue
    Write-Output "Cleared LID $p"
  }
  Clear-ImmersiveProperty
  Clear-TokenDeviceFields
  Clear-AuxCaches
}

function Invoke-Decoy {
  $newLid = New-DecoyLid
  Write-Output "DecoyLid=$newLid Gdid=$(ConvertTo-Gdid $newLid)"
  Clear-ImmersiveProperty
  foreach ($p in $LidPaths) {
    if ($DryRun) { Write-Output "DryRun set LID $p"; continue }
    Ensure-Key $p
    New-ItemProperty -Path $p -Name LID -Value $newLid -PropertyType String -Force | Out-Null
    Write-Output "Set LID $p"
  }
  Clear-TokenDeviceFields -NewDeviceId $newLid
  Clear-AuxCaches
}

function Invoke-Block {
  $present = Test-HostsBlockPresent
  if ($present) {
    Write-Output 'Hosts block already present; refreshing firewall rules...'
  } else {
    $block = @('', $MarkerBegin) + ($BlockHosts | ForEach-Object { "0.0.0.0 $_" }) + @($MarkerEnd, '')
    if ($DryRun) {
      Write-Output 'DryRun would append hosts:'
      $block | Write-Output
    } else {
      Add-Content -Path $HostsPath -Value ($block -join "`r`n") -Encoding ASCII
      Write-Output 'Hosts registration block appended.'
    }
  }

  if ($DryRun) {
    Write-Output 'DryRun would refresh outbound firewall block rules for resolved IPs.'
    return
  }

  ipconfig /flushdns | Out-Null
  $dnsServers = @('1.1.1.1', '8.8.8.8')
  foreach ($h in $BlockHosts) {
    $ruleName = "$RulePrefix$h"
    Get-NetFirewallRule -DisplayName $ruleName -EA SilentlyContinue | Remove-NetFirewallRule -EA SilentlyContinue
    $ips = @()
    foreach ($dns in $dnsServers) {
      try {
        $job = Start-Job -ScriptBlock {
          param($name, $server)
          Resolve-DnsName $name -Type A -Server $server -EA Stop |
            Where-Object { $_.IPAddress -and $_.IPAddress -ne '0.0.0.0' } |
            Select-Object -ExpandProperty IPAddress -Unique
        } -ArgumentList $h, $dns
        if (Wait-Job $job -Timeout 5) { $ips = @(Receive-Job $job) }
        Remove-Job $job -Force -EA SilentlyContinue
        if ($ips.Count -gt 0) { break }
      } catch {}
    }
    if (-not $ips -or $ips.Count -eq 0) {
      Write-Output "DNS miss for firewall IPs (hosts block still active): $h"
      continue
    }
    New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Block -RemoteAddress $ips -Protocol Any | Out-Null
    Write-Output "Firewall block $h ($($ips.Count) IPs)"
  }
  Write-Output "HostsBlockPresent=$(Test-HostsBlockPresent)"
}

function Invoke-Unblock {
  if ($DryRun) {
    Write-Output 'DryRun would remove hosts marker region and degdid firewall rules.'
    return
  }
  $c = @(Get-Content $HostsPath -EA SilentlyContinue)
  $out = New-Object System.Collections.Generic.List[string]
  $skip = $false
  foreach ($line in $c) {
    if ($line -eq $MarkerBegin) { $skip = $true; continue }
    if ($line -eq $MarkerEnd) { $skip = $false; continue }
    if (-not $skip) { $out.Add($line) }
  }
  Set-Content -Path $HostsPath -Value $out -Encoding ASCII
  ipconfig /flushdns | Out-Null
  Get-NetFirewallRule -DisplayName "$RulePrefix*" -EA SilentlyContinue | Remove-NetFirewallRule
  Write-Output 'Hosts block and degdid firewall rules removed.'
}

function Show-Status {
  $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
  Write-Output "=== degdid status $(Get-Date -Format o) ==="
  Write-Output "Build=$($cv.CurrentBuild) Display=$($cv.DisplayVersion) LooksOnline=$(Test-LooksOnline)"
  Write-Output '--- LID stores ---'
  $any = $false
  foreach ($p in $LidPaths) {
    $lid = Get-LidAt $p
    if ($lid) { $any = $true }
    $g = ConvertTo-Gdid $lid
    Write-Output ("{0} HasLid={1} Lid={2} Gdid={3}" -f $p, [bool]$lid, $(if ($lid) { $lid } else { '(none)' }), $(if ($g) { $g } else { '-' }))
  }
  $blobs = Get-ImmersivePropertyCount
  Write-Output "ImmersivePropertyBlobs=$blobs (rehydrate risk if >0 while LID cleared)"
  $tok = 'HKCU:\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Token'
  $did = 0
  if (Test-Path $tok) {
    Get-ChildItem $tok -EA SilentlyContinue | ForEach-Object {
      if ($null -ne (Get-ItemProperty $_.PSPath -EA SilentlyContinue).DeviceId) { $did++ }
    }
  }
  Write-Output "TokenDeviceIdKeys=$did"
  Write-Output "HostsBlockPresent=$(Test-HostsBlockPresent)"
  $fw = @(Get-NetFirewallRule -DisplayName "$RulePrefix*" -EA SilentlyContinue)
  Write-Output "FirewallBlockRules=$($fw.Count)"
  if ($any) {
    Write-Output 'Verdict: local GDID/LID PRESENT. Consider: .\degdid.ps1 -Protect'
  } elseif ($blobs -gt 0 -or $did -gt 0) {
    Write-Output 'Verdict: no LID, but leftover Immersive/Token state. Consider: .\degdid.ps1 -Protect'
  } elseif (-not (Test-HostsBlockPresent)) {
    Write-Output 'Verdict: no local LID, but registration NOT blocked - a future DeviceAdd can mint one.'
  } else {
    Write-Output 'Verdict: no local LID + registration blocks active (good for starve path).'
  }
}

Write-Output "=== degdid DryRun=$DryRun $(Get-Date -Format o) ==="

if ($Status) {
  Show-Status
  exit 0
}

if ($Unblock) {
  Invoke-Unblock
  Write-Output 'Done. Warning: without blocks, Windows may mint a real server GDID later.'
  exit 0
}

if ($Block) {
  Invoke-Block
  exit 0
}

if ($Protect) {
  Write-Output 'Protect: applying registration blocks, then local mutate...'
  Invoke-Block
  if ($UseDecoy) { Invoke-Decoy } else { Invoke-Wipe }
  Write-Output 'Done. Re-run: .\degdid.ps1 -Status'
  exit 0
}

# Wipe / Decoy alone - warn if online without blocks
$online = Test-LooksOnline
$blocked = Test-HostsBlockPresent
if ($online -and -not $blocked) {
  Write-Warning 'System looks online and registration is NOT blocked. A wipe/decoy alone can be followed by a server remint. Prefer: .\degdid.ps1 -Protect'
}

if ($Wipe) { Invoke-Wipe }
if ($Decoy) { Invoke-Decoy }

Write-Output 'Done. Re-run: .\degdid.ps1 -Status'
exit 0
