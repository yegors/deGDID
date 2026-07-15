#Requires -Version 5.1
<#
.SYNOPSIS
  Inspect, block, wipe, decoy, or unblock Microsoft GDID state on a supported
  unmanaged Windows installation with one loaded target human-profile hive.

.DESCRIPTION
  degdid resolves the active interactive user explicitly and addresses that
  user's loaded HKEY_USERS hive. Mutating actions refuse domain-joined,
  Entra-joined, MDM-enrolled, multiple-loaded-human-profile, unsupported
  Windows-build, or unloaded-target-hive systems.

  Protect refreshes a canonical dual-stack hosts region and Windows Firewall
  dynamic-keyword FQDN rules, verifies the mint path is blocked, then performs
  the identity mutation. Wipe is the canonical identity action. Decoy remains
  experimental.

.PARAMETER Status
  Report the environment, target user, hosts, firewall, mint path, active GDID
  stores, residual caches, and one machine-readable verdict. This is the
  default action and may run on unsupported systems.

.PARAMETER Wipe
  Clear target-user, SYSTEM, and .DEFAULT GDID state. Existing registration
  blocks must independently verify before the wipe can begin.

.PARAMETER Decoy
  Experimental. Clear old GDID state and install one generated 0018-shaped
  local decoy consistently. Existing registration blocks must verify first.

.PARAMETER Block
  Refresh the canonical IPv4/IPv6 hosts region and dynamic-keyword outbound
  firewall rule, then independently verify the mint-critical path.

.PARAMETER Unblock
  Remove the current managed hosts region, dynamic keywords, and firewall rules.
  A malformed, noncanonical, or duplicate hosts region is
  never guessed at or rewritten.

.PARAMETER Protect
  Apply and verify registration blocks, then Wipe by default or Decoy when
  UseDecoy is supplied. Identity state is not touched if the block gate fails.

.PARAMETER UseDecoy
  Use the experimental Decoy mutation with Protect instead of Wipe.

.PARAMETER DryRun
  Inspect and report planned work without changing hosts, firewall, services,
  registry, or files. DryRun never claims that planned blocks are active.

.PARAMETER Json
  Emit Status as JSON.

.PARAMETER InternalNoExit
  Test seam: load functions without invoking an action or exiting the caller.

.NOTES
  Exit codes: 0 success; 1 unexpected/admin failure; 2 unsupported mutation;
  3 block verification failure; 4 safe-hosts refusal; 5 wipe/postcondition
  failure; 6 target-user failure.

  This does not erase Microsoft server-side history or stop every telemetry
  plane. Blocking login.live.com intentionally breaks or degrades MSA, Store,
  Xbox, OneDrive sign-in, Phone Link, and related identity features.
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

  [Parameter(ParameterSetName = 'Status')]
  [switch]$Json,

  [switch]$DryRun,

  [Parameter(DontShow = $true)]
  [switch]$InternalNoExit
)

$script:MarkerBegin = '# BEGIN degdid-registration-block'
$script:MarkerEnd = '# END degdid-registration-block'
$script:HostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$script:HostsMutexName = 'Global\degdid-hosts-v2'
$script:FirewallRuleName = 'degdid-block-fqdn-v2'
$script:FirewallRuleDisplayName = 'degdid-block-fqdn-v2'
$script:MintServiceRuleName = 'degdid-block-wlidsvc-v2'
$script:MintServiceRuleDisplayName = 'degdid-block-wlidsvc-v2'
$script:StagingMintServiceRuleName = 'degdid-stage-wlidsvc-v2'
$script:StagingMintServiceRuleDisplayName = 'degdid-stage-wlidsvc-v2'
$script:FirewallGroup = 'degdid managed registration blocks'
$script:MintHost = 'login.live.com'
$script:SettleSeconds = 12
$script:DegdidExitCode = 0
$script:Windows10SupportedBuild = 19045
$script:LabValidatedBuild = 26200
$script:LabValidatedDisplayVersion = '25H2'
$script:DeviceCredentialTargets = @(
  'MicrosoftAccount:target=SSO_POP_Device',
  'WindowsLive:target=virtualapp/didlogical'
)

$script:BlockHosts = @(
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

function Test-RealPuid {
  param([AllowNull()][string]$Value)

  return [bool]($Value -and $Value -match '^0018[0-9A-Fa-f]{12}$')
}

function Test-SupportedWindowsBuild {
  param([int]$Build)

  return (
    $Build -eq $script:Windows10SupportedBuild -or
    $Build -ge 22000
  )
}

function ConvertTo-Gdid {
  param([AllowNull()][string]$Lid)

  if (-not $Lid -or $Lid -notmatch '^[0-9A-Fa-f]{16}$') {
    return $null
  }

  try {
    return 'g:{0}' -f [Convert]::ToUInt64($Lid, 16)
  } catch {
    return $null
  }
}

function Get-Sha256Hex {
  param([AllowNull()][string]$Value)

  if ($null -eq $Value) {
    return $null
  }

  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
    return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
  } finally {
    $sha.Dispose()
  }
}

function Get-EmbeddedRealPuids {
  param([AllowNull()][string]$Value)

  if (-not $Value) {
    return @()
  }

  $found = @(
    [regex]::Matches(
      $Value,
      '(?i)(?<![0-9a-f])0018[0-9a-f]{12}(?![0-9a-f])'
    ) | ForEach-Object { $_.Value.ToUpperInvariant() }
  )
  return @($found | Select-Object -Unique)
}

function New-DecoyLid {
  $bytes = New-Object byte[] 6
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try {
    $rng.GetBytes($bytes)
  } finally {
    $rng.Dispose()
  }
  return '0018' + (($bytes | ForEach-Object { $_.ToString('X2') }) -join '')
}

function Get-CanonicalHostsRegionLines {
  param([string[]]$Hosts = $script:BlockHosts)

  $lines = New-Object System.Collections.Generic.List[string]
  [void]$lines.Add($script:MarkerBegin)
  foreach ($hostName in $Hosts) {
    [void]$lines.Add(('0.0.0.0 {0}' -f $hostName.ToLowerInvariant()))
    [void]$lines.Add((':: {0}' -f $hostName.ToLowerInvariant()))
  }
  [void]$lines.Add($script:MarkerEnd)
  return $lines.ToArray()
}

function Get-HostsLineRecords {
  param([AllowEmptyString()][string]$Text)

  $records = New-Object System.Collections.Generic.List[object]
  $position = 0
  $index = 0

  while ($position -lt $Text.Length) {
    $start = $position
    while (
      $position -lt $Text.Length -and
      $Text[$position] -ne "`r" -and
      $Text[$position] -ne "`n"
    ) {
      $position++
    }

    $contentEnd = $position
    $newLine = ''
    if ($position -lt $Text.Length) {
      if (
        $Text[$position] -eq "`r" -and
        ($position + 1) -lt $Text.Length -and
        $Text[$position + 1] -eq "`n"
      ) {
        $newLine = "`r`n"
        $position += 2
      } else {
        $newLine = [string]$Text[$position]
        $position++
      }
    }

    [void]$records.Add([pscustomobject]@{
      Index = $index
      Start = $start
      ContentEnd = $contentEnd
      End = $position
      Content = $Text.Substring($start, $contentEnd - $start)
      NewLine = $newLine
    })
    $index++
  }

  return $records.ToArray()
}

function Get-HostsDocumentState {
  param(
    [AllowEmptyString()][string]$Text,
    [string[]]$Hosts = $script:BlockHosts
  )

  $records = @(Get-HostsLineRecords -Text $Text)
  $beginLikeRecords = @(
    $records |
      Where-Object {
        $_.Content -match '(?i)^\s*#\s*BEGIN\s+degdid-registration-block\b'
      }
  )
  $endLikeRecords = @(
    $records |
      Where-Object {
        $_.Content -match '(?i)^\s*#\s*END\s+degdid-registration-block\b'
      }
  )
  $beginRecords = @(
    $records | Where-Object { $_.Content -ceq $script:MarkerBegin }
  )
  $endRecords = @(
    $records | Where-Object { $_.Content -ceq $script:MarkerEnd }
  )

  $preferredNewLine = "`r`n"
  foreach ($record in $records) {
    if ($record.NewLine) {
      $preferredNewLine = $record.NewLine
      break
    }
  }

  $endsWithNewLine = $false
  if ($records.Count -gt 0) {
    $endsWithNewLine = [bool]$records[$records.Count - 1].NewLine
  }

  $state = 'Absent'
  $beginIndex = -1
  $endIndex = -1
  $regionStart = -1
  $regionEnd = -1
  $scanRecords = @()
  $canonical = $false

  if ($beginRecords.Count -eq 0 -and $endRecords.Count -eq 0) {
    if ($beginLikeRecords.Count -gt 0 -or $endLikeRecords.Count -gt 0) {
      $state = 'Malformed'
      $scanRecords = $records
    } else {
      $state = 'Absent'
    }
  } elseif ($beginRecords.Count -gt 1 -or $endRecords.Count -gt 1) {
    $state = 'Duplicate'
    $scanRecords = $records
  } elseif ($beginRecords.Count -ne 1 -or $endRecords.Count -ne 1) {
    $state = 'Malformed'
    $scanRecords = $records
  } else {
    $beginIndex = [int]$beginRecords[0].Index
    $endIndex = [int]$endRecords[0].Index
    if ($beginIndex -ge $endIndex) {
      $state = 'Malformed'
      $scanRecords = $records
    } else {
      $regionStart = [int]$records[$beginIndex].Start
      $regionEnd = [int]$records[$endIndex].End
      if ($endIndex -gt ($beginIndex + 1)) {
        $scanRecords = @($records[($beginIndex + 1)..($endIndex - 1)])
      }

      $expected = @(
        (Get-CanonicalHostsRegionLines -Hosts $Hosts)[1..((2 * $Hosts.Count))]
      )
      $actual = @($scanRecords | ForEach-Object { $_.Content })
      $ownedContent = $true
      foreach ($line in $actual) {
        if (
          $line -ne '' -and
          $line -notmatch '^\s*(0\.0\.0\.0|::)\s+[A-Za-z0-9.-]+\s*$'
        ) {
          $ownedContent = $false
          break
        }
      }
      if (-not $ownedContent) {
        $state = 'Malformed'
        $canonical = $false
      }
      $canonical = $actual.Count -eq $expected.Count
      if ($canonical) {
        for ($i = 0; $i -lt $expected.Count; $i++) {
          if ($actual[$i] -cne $expected[$i]) {
            $canonical = $false
            break
          }
        }
      }
      # Structurally paired content is classified separately from canonical
      # current-format content so callers can refuse noncanonical state.
      if ($ownedContent) {
        $state = 'Valid'
      }
    }
  }

  $ipv4Names = New-Object System.Collections.Generic.List[string]
  $ipv6Names = New-Object System.Collections.Generic.List[string]
  foreach ($record in $scanRecords) {
    if ($record.Content -match '^\s*(0\.0\.0\.0|::)\s+([^\s#]+)\s*$') {
      $address = $matches[1]
      $name = $matches[2].ToLowerInvariant()
      if ($Hosts -contains $name) {
        if ($address -eq '0.0.0.0' -and -not $ipv4Names.Contains($name)) {
          [void]$ipv4Names.Add($name)
        }
        if ($address -eq '::' -and -not $ipv6Names.Contains($name)) {
          [void]$ipv6Names.Add($name)
        }
      }
    }
  }

  $missingIPv4 = @($Hosts | Where-Object { -not $ipv4Names.Contains($_) })
  $missingIPv6 = @($Hosts | Where-Object { -not $ipv6Names.Contains($_) })

  return [pscustomobject]@{
    State = $state
    BeginCount = $beginRecords.Count
    EndCount = $endRecords.Count
    BeginIndex = $beginIndex
    EndIndex = $endIndex
    RegionStart = $regionStart
    RegionEnd = $regionEnd
    Canonical = $canonical
    Records = $records
    PreferredNewLine = $preferredNewLine
    EndsWithNewLine = $endsWithNewLine
    IPv4Names = $ipv4Names.ToArray()
    IPv6Names = $ipv6Names.ToArray()
    IPv4Count = $ipv4Names.Count
    IPv6Count = $ipv6Names.Count
    MissingIPv4 = $missingIPv4
    MissingIPv6 = $missingIPv6
  }
}

function Set-GdidHostsRegionText {
  param(
    [AllowEmptyString()][string]$Text,
    [string[]]$Hosts = $script:BlockHosts
  )

  $state = Get-HostsDocumentState -Text $Text -Hosts $Hosts
  if ($state.State -eq 'Malformed' -or $state.State -eq 'Duplicate') {
    throw [System.IO.InvalidDataException]::new(
      'Managed hosts region is {0}; refusing to guess.' -f $state.State
    )
  }
  if ($state.State -eq 'Valid' -and -not $state.Canonical) {
    throw [System.IO.InvalidDataException]::new(
      'Managed hosts region is not current canonical format.'
    )
  }

  $lines = @(Get-CanonicalHostsRegionLines -Hosts $Hosts)
  $newLine = $state.PreferredNewLine

  if ($state.State -eq 'Valid') {
    $beginRecord = $state.Records[$state.BeginIndex]
    $endRecord = $state.Records[$state.EndIndex]
    if ($beginRecord.NewLine) {
      $newLine = $beginRecord.NewLine
    }
    $replacement = $lines -join $newLine
    if ($endRecord.NewLine) {
      $replacement += $endRecord.NewLine
    }
    return (
      $Text.Substring(0, $state.RegionStart) +
      $replacement +
      $Text.Substring($state.RegionEnd)
    )
  }

  $region = $lines -join $newLine
  if ($Text.Length -eq 0) {
    return $region + $newLine
  }
  if ($state.EndsWithNewLine) {
    return $Text + $region + $newLine
  }
  return $Text + $newLine + $region
}

function Remove-GdidHostsRegionText {
  param(
    [AllowEmptyString()][string]$Text,
    [string[]]$Hosts = $script:BlockHosts
  )

  $state = Get-HostsDocumentState -Text $Text -Hosts $Hosts
  if ($state.State -eq 'Absent') {
    return $Text
  }
  if ($state.State -ne 'Valid' -or -not $state.Canonical) {
    throw [System.IO.InvalidDataException]::new(
      'Managed hosts region is not current canonical format.'
    )
  }

  return (
    $Text.Substring(0, $state.RegionStart) +
    $Text.Substring($state.RegionEnd)
  )
}

function Test-ByteArrayEqual {
  param(
    [byte[]]$Left,
    [byte[]]$Right
  )

  if ($Left.Length -ne $Right.Length) {
    return $false
  }
  for ($i = 0; $i -lt $Left.Length; $i++) {
    if ($Left[$i] -ne $Right[$i]) {
      return $false
    }
  }
  return $true
}

function ConvertFrom-HostsBytes {
  param([byte[]]$Bytes)

  $bomLength = 0
  $encodingName = ''
  $encoding = $null

  if (
    $Bytes.Length -ge 4 -and
    $Bytes[0] -eq 0x00 -and $Bytes[1] -eq 0x00 -and
    $Bytes[2] -eq 0xFE -and $Bytes[3] -eq 0xFF
  ) {
    $bomLength = 4
    $encodingName = 'utf-32BE'
    $encoding = [System.Text.UTF32Encoding]::new($true, $false, $true)
  } elseif (
    $Bytes.Length -ge 4 -and
    $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE -and
    $Bytes[2] -eq 0x00 -and $Bytes[3] -eq 0x00
  ) {
    $bomLength = 4
    $encodingName = 'utf-32LE'
    $encoding = [System.Text.UTF32Encoding]::new($false, $false, $true)
  } elseif (
    $Bytes.Length -ge 3 -and
    $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF
  ) {
    $bomLength = 3
    $encodingName = 'utf-8'
    $encoding = [System.Text.UTF8Encoding]::new($false, $true)
  } elseif (
    $Bytes.Length -ge 2 -and
    $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE
  ) {
    $bomLength = 2
    $encodingName = 'utf-16LE'
    $encoding = [System.Text.UnicodeEncoding]::new($false, $false, $true)
  } elseif (
    $Bytes.Length -ge 2 -and
    $Bytes[0] -eq 0xFE -and $Bytes[1] -eq 0xFF
  ) {
    $bomLength = 2
    $encodingName = 'utf-16BE'
    $encoding = [System.Text.UnicodeEncoding]::new($true, $false, $true)
  }

  $payloadLength = $Bytes.Length - $bomLength
  $payload = New-Object byte[] $payloadLength
  if ($payloadLength -gt 0) {
    [Array]::Copy($Bytes, $bomLength, $payload, 0, $payloadLength)
  }

  if ($null -eq $encoding -and $payload.Length -ge 4) {
    $nullRatios = @()
    for ($offset = 0; $offset -lt 4; $offset++) {
      $sampleCount = 0
      $nullCount = 0
      for ($i = $offset; $i -lt $payload.Length; $i += 4) {
        $sampleCount++
        if ($payload[$i] -eq 0) {
          $nullCount++
        }
      }
      $nullRatios += $(if ($sampleCount -gt 0) {
        [double]$nullCount / [double]$sampleCount
      } else {
        0.0
      })
    }

    if (
      $payload.Length % 4 -eq 0 -and
      $nullRatios[0] -lt 0.40 -and
      $nullRatios[1] -gt 0.60 -and
      $nullRatios[2] -gt 0.60 -and
      $nullRatios[3] -gt 0.60
    ) {
      $encoding = [System.Text.UTF32Encoding]::new($false, $false, $true)
      $encodingName = 'utf-32LE-no-bom'
    } elseif (
      $payload.Length % 4 -eq 0 -and
      $nullRatios[0] -gt 0.60 -and
      $nullRatios[1] -gt 0.60 -and
      $nullRatios[2] -gt 0.60 -and
      $nullRatios[3] -lt 0.40
    ) {
      $encoding = [System.Text.UTF32Encoding]::new($true, $false, $true)
      $encodingName = 'utf-32BE-no-bom'
    }
  }

  if (
    $null -eq $encoding -and
    $payload.Length -ge 2 -and
    $payload.Length % 2 -eq 0
  ) {
    $evenNulls = 0
    $oddNulls = 0
    $pairs = [int]($payload.Length / 2)
    for ($i = 0; $i -lt $payload.Length; $i += 2) {
      if ($payload[$i] -eq 0) {
        $evenNulls++
      }
      if ($payload[$i + 1] -eq 0) {
        $oddNulls++
      }
    }
    $evenRatio = [double]$evenNulls / [double]$pairs
    $oddRatio = [double]$oddNulls / [double]$pairs
    if ($oddRatio -gt 0.60 -and $evenRatio -lt 0.30) {
      $encoding = [System.Text.UnicodeEncoding]::new($false, $false, $true)
      $encodingName = 'utf-16LE-no-bom'
    } elseif ($evenRatio -gt 0.60 -and $oddRatio -lt 0.30) {
      $encoding = [System.Text.UnicodeEncoding]::new($true, $false, $true)
      $encodingName = 'utf-16BE-no-bom'
    }
  }

  if ($null -eq $encoding) {
    $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
    try {
      $utf8Text = $utf8.GetString($payload)
      if (Test-ByteArrayEqual -Left $payload -Right $utf8.GetBytes($utf8Text)) {
        $encoding = $utf8
        $encodingName = 'utf-8-no-bom'
      }
    } catch {
      $encoding = $null
    }
  }

  if ($null -eq $encoding) {
    $encoding = [System.Text.Encoding]::GetEncoding(
      [System.Text.Encoding]::Default.CodePage,
      [System.Text.EncoderExceptionFallback]::new(),
      [System.Text.DecoderExceptionFallback]::new()
    )
    $encodingName = 'ansi-{0}' -f $encoding.CodePage
  }

  try {
    $text = $encoding.GetString($payload)
    $roundTrip = $encoding.GetBytes($text)
  } catch {
    throw [System.IO.InvalidDataException]::new(
      'Hosts encoding could not be decoded losslessly.',
      $_.Exception
    )
  }

  if (-not (Test-ByteArrayEqual -Left $payload -Right $roundTrip)) {
    throw [System.IO.InvalidDataException]::new(
      'Hosts encoding did not round-trip losslessly.'
    )
  }

  $bom = New-Object byte[] $bomLength
  if ($bomLength -gt 0) {
    [Array]::Copy($Bytes, 0, $bom, 0, $bomLength)
  }

  return [pscustomobject]@{
    Text = $text
    Encoding = $encoding
    EncodingName = $encodingName
    Bom = $bom
    BomLength = $bomLength
  }
}

function ConvertTo-HostsBytes {
  param(
    [AllowEmptyString()][string]$Text,
    [System.Text.Encoding]$Encoding,
    [byte[]]$Bom
  )

  $payload = $Encoding.GetBytes($Text)
  $result = New-Object byte[] ($Bom.Length + $payload.Length)
  if ($Bom.Length -gt 0) {
    [Array]::Copy($Bom, 0, $result, 0, $Bom.Length)
  }
  if ($payload.Length -gt 0) {
    [Array]::Copy($payload, 0, $result, $Bom.Length, $payload.Length)
  }
  return ,$result
}

function Read-HostsDocument {
  param([string]$Path = $script:HostsPath)

  if (-not [System.IO.File]::Exists($Path)) {
    throw [System.IO.FileNotFoundException]::new('Hosts file does not exist.', $Path)
  }
  if (
    ([System.IO.File]::GetAttributes($Path) -band
      [System.IO.FileAttributes]::ReparsePoint) -ne 0
  ) {
    throw [System.IO.InvalidDataException]::new(
      'Hosts file is a reparse point; refusing to follow it.'
    )
  }
  $bytes = [System.IO.File]::ReadAllBytes($Path)
  $decoded = ConvertFrom-HostsBytes -Bytes $bytes
  $state = Get-HostsDocumentState -Text $decoded.Text
  return [pscustomobject]@{
    Path = $Path
    Bytes = $bytes
    Text = $decoded.Text
    Encoding = $decoded.Encoding
    EncodingName = $decoded.EncodingName
    Bom = $decoded.Bom
    State = $state
  }
}

function Write-HostsDocumentAtomic {
  param(
    [string]$Path,
    [byte[]]$Bytes,
    [byte[]]$ExpectedOriginalBytes
  )

  $directory = [System.IO.Path]::GetDirectoryName($Path)
  $leaf = [System.IO.Path]::GetFileName($Path)
  $backup = Join-Path $directory (
    '{0}.degdid.{1}.{2}.bak' -f
    $leaf,
    (Get-Date -Format 'yyyyMMddHHmmssfff'),
    [Guid]::NewGuid().ToString('N')
  )
  $temporary = Join-Path $directory (
    '.{0}.degdid.{1}.tmp' -f $leaf, [Guid]::NewGuid().ToString('N')
  )

  try {
    $currentBytes = [System.IO.File]::ReadAllBytes($Path)
    if (-not (Test-ByteArrayEqual -Left $currentBytes -Right $ExpectedOriginalBytes)) {
      throw [System.IO.IOException]::new(
        'Hosts changed after it was read; refusing to overwrite concurrent edits.'
      )
    }
    [System.IO.File]::WriteAllBytes($temporary, $Bytes)
    [System.IO.File]::Replace($temporary, $Path, $backup, $false)
  } finally {
    if ([System.IO.File]::Exists($temporary)) {
      [System.IO.File]::Delete($temporary)
    }
  }
}

function Invoke-WithHostsMutex {
  param([scriptblock]$Action)

  $mutex = [System.Threading.Mutex]::new($false, $script:HostsMutexName)
  $acquired = $false
  try {
    try {
      $acquired = $mutex.WaitOne([TimeSpan]::FromSeconds(15))
    } catch [System.Threading.AbandonedMutexException] {
      $acquired = $true
    }
    if (-not $acquired) {
      throw [System.TimeoutException]::new('Timed out waiting for the hosts mutex.')
    }
    return & $Action
  } finally {
    if ($acquired) {
      [void]$mutex.ReleaseMutex()
    }
    $mutex.Dispose()
  }
}

function Invoke-HostsDocumentChange {
  param(
    [ValidateSet('Block', 'Unblock')]
    [string]$Mode,
    [switch]$DryRun
  )

  $operation = {
    $document = Read-HostsDocument
    if ($document.State.State -eq 'Malformed' -or $document.State.State -eq 'Duplicate') {
      throw [System.IO.InvalidDataException]::new(
        'Managed hosts region is {0}; refusing to rewrite hosts.' -f
        $document.State.State
      )
    }

    if ($Mode -eq 'Block') {
      $newText = Set-GdidHostsRegionText -Text $document.Text
    } else {
      $newText = Remove-GdidHostsRegionText -Text $document.Text
    }
    $newState = Get-HostsDocumentState -Text $newText
    $changed = $newText -cne $document.Text

    if (-not $DryRun) {
      if ($changed) {
        $bytes = ConvertTo-HostsBytes `
          -Text $newText `
          -Encoding $document.Encoding `
          -Bom $document.Bom
        Write-HostsDocumentAtomic `
          -Path $document.Path `
          -Bytes $bytes `
          -ExpectedOriginalBytes $document.Bytes
      }
    }

    return [pscustomobject]@{
      Mode = $Mode
      DryRun = [bool]$DryRun
      Changed = $changed
      StateBefore = $document.State.State
      StateAfter = $newState.State
      Encoding = $document.EncodingName
    }
  }

  if ($DryRun) {
    return & $operation
  }
  return Invoke-WithHostsMutex -Action $operation
}

function Get-DynamicKeywordId {
  param([string]$HostName)

  $seed = 'degdid-fqdn-v2:' + $HostName.ToLowerInvariant()
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $hash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($seed))
  } finally {
    $sha.Dispose()
  }

  $bytes = New-Object byte[] 16
  [Array]::Copy($hash, $bytes, 16)
  $bytes[7] = [byte](($bytes[7] -band 0x0F) -bor 0x50)
  $bytes[8] = [byte](($bytes[8] -band 0x3F) -bor 0x80)
  return ([Guid]::new($bytes)).ToString('B')
}

function Test-DynamicFirewallSupport {
  $required = @(
    'Get-NetFirewallDynamicKeywordAddress',
    'New-NetFirewallDynamicKeywordAddress',
    'Remove-NetFirewallDynamicKeywordAddress',
    'Get-NetFirewallApplicationFilter',
    'Get-NetFirewallPortFilter',
    'Get-NetFirewallProfile',
    'Get-NetFirewallRule',
    'Get-NetFirewallServiceFilter',
    'New-NetFirewallRule',
    'Remove-NetFirewallRule'
  )
  foreach ($commandName in $required) {
    if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
      return $false
    }
  }
  return $true
}

function Get-AllDynamicKeywordObjects {
  return @(
    Get-NetFirewallDynamicKeywordAddress `
      -All `
      -PolicyStore ActiveStore `
      -ErrorAction Stop
  )
}

function ConvertTo-NormalizedGuidText {
  param([AllowNull()][string]$Value)

  if (-not $Value) {
    return ''
  }
  return $Value.Trim().Trim('{', '}').ToLowerInvariant()
}

function Test-StringSetEqual {
  param(
    [string[]]$Left,
    [string[]]$Right
  )

  $a = @($Left | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)
  $b = @($Right | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)
  if ($a.Count -ne $b.Count) {
    return $false
  }
  for ($i = 0; $i -lt $a.Count; $i++) {
    if ($a[$i] -cne $b[$i]) {
      return $false
    }
  }
  return $true
}

function Test-FirewallEnforcementStatus {
  param([AllowNull()][string]$Status)

  if (-not $Status) {
    return $false
  }
  return (
    $Status -match '(?i)\b(Full|Enforced)\b' -and
    $Status -notmatch '(?i)(Disallowed|Disabled|Error|NoRemoteAddress|NoApplication|NotTarget|FirewallOff)'
  )
}

function Get-FirewallState {
  if (-not (Test-DynamicFirewallSupport)) {
    return [pscustomobject]@{
      Available = $false
      Health = 'Unavailable'
      KeywordCount = 0
      MissingKeywords = @($script:BlockHosts)
      InvalidKeywords = @()
      RuleCount = 0
      RuleValid = $false
      FqdnRuleEnforcement = 'Unavailable'
      MintServiceRuleCount = 0
      MintServiceRuleValid = $false
      MintServiceRuleEnforcement = 'Unavailable'
      StagingRuleCount = 0
      HydratedKeywordCount = 0
      MintKeywordHydrated = $false
      InfrastructureHealthy = $false
      Errors = @()
    }
  }

  $errors = New-Object System.Collections.Generic.List[string]
  $missing = New-Object System.Collections.Generic.List[string]
  $invalid = New-Object System.Collections.Generic.List[string]
  $keywordCount = 0
  $hydratedKeywordCount = 0
  $mintKeywordHydrated = $false
  $allKeywordObjects = @()

  try {
    $allKeywordObjects = @(Get-AllDynamicKeywordObjects)
  } catch {
    [void]$errors.Add(('Keywords: {0}' -f $_.Exception.Message))
  }

  if ($errors.Count -eq 0) {
    foreach ($hostName in $script:BlockHosts) {
      $id = ConvertTo-NormalizedGuidText (Get-DynamicKeywordId $hostName)
      $objects = @(
        $allKeywordObjects |
          Where-Object { (ConvertTo-NormalizedGuidText $_.Id) -eq $id }
      )
      if ($objects.Count -eq 0) {
        [void]$missing.Add($hostName)
        continue
      }
      $keywordCount += $objects.Count
      if (
        $objects.Count -ne 1 -or
        $objects[0].Keyword -ine $hostName -or
        -not [bool]$objects[0].AutoResolve
      ) {
        [void]$invalid.Add($hostName)
      }
      if (
        $objects.Count -eq 1 -and
        @($objects[0].Addresses | Where-Object { $_ }).Count -gt 0
      ) {
        $hydratedKeywordCount++
        if ($hostName -ieq $script:MintHost) {
          $mintKeywordHydrated = $true
        }
      }
    }
  }

  $rules = @()
  $mintServiceRules = @()
  $stagingRules = @()
  try {
    $rules = @(
      Get-NetFirewallRule `
        -DisplayName $script:FirewallRuleDisplayName `
        -PolicyStore ActiveStore `
        -ErrorAction SilentlyContinue
    )
    $mintServiceRules = @(
      Get-NetFirewallRule `
        -Name $script:MintServiceRuleName `
        -PolicyStore ActiveStore `
        -ErrorAction SilentlyContinue
    )
    $stagingRules = @(
      Get-NetFirewallRule `
        -Name $script:StagingMintServiceRuleName `
        -PolicyStore ActiveStore `
        -ErrorAction SilentlyContinue
    )
  } catch {
    [void]$errors.Add(('Rules: {0}' -f $_.Exception.Message))
  }

  $ruleValid = $false
  $fqdnRuleEnforcement = 'Absent'
  if ($rules.Count -eq 1) {
    $fqdnRuleEnforcement = [string]$rules[0].EnforcementStatus
    $expectedIds = @(
      $script:BlockHosts |
        ForEach-Object { ConvertTo-NormalizedGuidText (Get-DynamicKeywordId $_) }
    )
    $actualIds = @(
      $rules[0].RemoteDynamicKeywordAddresses |
        ForEach-Object { ConvertTo-NormalizedGuidText $_ }
    )
    try {
      $applicationFilters = @(
        Get-NetFirewallApplicationFilter `
          -AssociatedNetFirewallRule $rules[0] `
          -ErrorAction Stop
      )
      $serviceFilters = @(
        Get-NetFirewallServiceFilter `
          -AssociatedNetFirewallRule $rules[0] `
          -ErrorAction Stop
      )
      $portFilters = @(
        Get-NetFirewallPortFilter `
          -AssociatedNetFirewallRule $rules[0] `
          -ErrorAction Stop
      )
      $ruleValid = (
        $rules[0].Direction.ToString() -eq 'Outbound' -and
        $rules[0].Action.ToString() -eq 'Block' -and
        $rules[0].Enabled.ToString() -eq 'True' -and
        $rules[0].Profile.ToString() -eq 'Any' -and
        (Test-StringSetEqual -Left $actualIds -Right $expectedIds) -and
        $applicationFilters.Count -eq 1 -and
        $applicationFilters[0].Program -eq 'Any' -and
        $serviceFilters.Count -eq 1 -and
        $serviceFilters[0].Service -eq 'Any' -and
        $portFilters.Count -eq 1 -and
        $portFilters[0].Protocol.ToString() -eq 'Any'
      )
    } catch {
      [void]$errors.Add(('FQDN rule filters: {0}' -f $_.Exception.Message))
    }
  }

  $mintServiceRuleValid = $false
  $mintServiceRuleEnforcement = 'Absent'
  if ($mintServiceRules.Count -eq 1) {
    $mintServiceRuleEnforcement = [string]$mintServiceRules[0].EnforcementStatus
    try {
      $serviceFilters = @(
        Get-NetFirewallServiceFilter `
          -AssociatedNetFirewallRule $mintServiceRules[0] `
          -ErrorAction Stop
      )
      $applicationFilters = @(
        Get-NetFirewallApplicationFilter `
          -AssociatedNetFirewallRule $mintServiceRules[0] `
          -ErrorAction Stop
      )
      $portFilters = @(
        Get-NetFirewallPortFilter `
          -AssociatedNetFirewallRule $mintServiceRules[0] `
          -ErrorAction Stop
      )
      $expectedProgram = Join-Path $env:SystemRoot 'System32\svchost.exe'
      $mintServiceRuleValid = (
        $mintServiceRules[0].Direction.ToString() -eq 'Outbound' -and
        $mintServiceRules[0].Action.ToString() -eq 'Block' -and
        $mintServiceRules[0].Enabled.ToString() -eq 'True' -and
        (Test-FirewallEnforcementStatus $mintServiceRuleEnforcement) -and
        $mintServiceRules[0].Profile.ToString() -eq 'Any' -and
        $serviceFilters.Count -eq 1 -and
        $serviceFilters[0].Service -ieq 'wlidsvc' -and
        $applicationFilters.Count -eq 1 -and
        $applicationFilters[0].Program -ieq $expectedProgram -and
        $portFilters.Count -eq 1 -and
        $portFilters[0].Protocol.ToString() -eq 'Any'
      )
    } catch {
      [void]$errors.Add(('Mint service rule: {0}' -f $_.Exception.Message))
    }
  }

  $infrastructureHealthy = $false
  try {
    $firewallService = Get-Service -Name MpsSvc -ErrorAction Stop
    $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    $infrastructureHealthy = (
      $firewallService.Status -eq 'Running' -and
      $profiles.Count -gt 0 -and
      @(
        $profiles |
          Where-Object {
            $_.Enabled.ToString() -ne 'True' -or
            ([string]$_.AllowLocalFirewallRules) -eq 'False'
          }
      ).Count -eq 0
    )
  } catch {
    [void]$errors.Add(('Firewall infrastructure: {0}' -f $_.Exception.Message))
  }

  $health = 'Malformed'
  if ($errors.Count -gt 0) {
    $health = 'Error'
  } elseif (
    $keywordCount -eq 0 -and
    $rules.Count -eq 0 -and
    $mintServiceRules.Count -eq 0 -and
    $stagingRules.Count -eq 0
  ) {
    $health = 'Absent'
  } elseif (
    $missing.Count -eq 0 -and
    $invalid.Count -eq 0 -and
    $ruleValid -and
    $mintServiceRuleValid -and
    $infrastructureHealthy
  ) {
    $health = 'Valid'
  }

  return [pscustomobject]@{
    Available = $true
    Health = $health
    KeywordCount = $keywordCount
    MissingKeywords = $missing.ToArray()
    InvalidKeywords = $invalid.ToArray()
    RuleCount = $rules.Count + $mintServiceRules.Count
    RuleValid = $ruleValid
    FqdnRuleEnforcement = $fqdnRuleEnforcement
    MintServiceRuleCount = $mintServiceRules.Count
    MintServiceRuleValid = $mintServiceRuleValid
    MintServiceRuleEnforcement = $mintServiceRuleEnforcement
    StagingRuleCount = $stagingRules.Count
    HydratedKeywordCount = $hydratedKeywordCount
    MintKeywordHydrated = $mintKeywordHydrated
    InfrastructureHealthy = $infrastructureHealthy
    Errors = $errors.ToArray()
  }
}

function Remove-ManagedFirewallRules {
  param([switch]$PreserveMintServiceRule)

  $namedRule = @(
    Get-NetFirewallRule `
      -Name $script:FirewallRuleName `
      -ErrorAction SilentlyContinue
  )
  $mintNamedRule = @(
    Get-NetFirewallRule `
      -Name $script:MintServiceRuleName `
      -ErrorAction SilentlyContinue
  )
  $allRules = @(
    $namedRule + $mintNamedRule |
      Sort-Object Name -Unique
  )
  foreach ($rule in $allRules) {
    if (
      $PreserveMintServiceRule -and
      $rule.Name -eq $script:MintServiceRuleName
    ) {
      continue
    }
    Remove-NetFirewallRule -InputObject $rule -ErrorAction Stop
  }
}

function Remove-StagingMintServiceRule {
  $rules = @(
    Get-NetFirewallRule `
      -Name $script:StagingMintServiceRuleName `
      -ErrorAction SilentlyContinue
  )
  foreach ($rule in $rules) {
    Remove-NetFirewallRule -InputObject $rule -ErrorAction Stop
  }
}

function New-StagingMintServiceRule {
  Remove-StagingMintServiceRule
  New-NetFirewallRule `
    -Name $script:StagingMintServiceRuleName `
    -DisplayName $script:StagingMintServiceRuleDisplayName `
    -Group $script:FirewallGroup `
    -Description 'degdid temporary fail-closed wlidsvc deny during refresh' `
    -Direction Outbound `
    -Action Block `
    -Enabled True `
    -Profile Any `
    -Protocol Any `
    -Program (Join-Path $env:SystemRoot 'System32\svchost.exe') `
    -Service 'wlidsvc' `
    -ErrorAction Stop | Out-Null
}

function Test-StagingMintServiceRuleEnforced {
  try {
    $rules = @(
      Get-NetFirewallRule `
        -Name $script:StagingMintServiceRuleName `
        -PolicyStore ActiveStore `
        -ErrorAction Stop
    )
    if (
      $rules.Count -ne 1 -or
      -not (Test-FirewallEnforcementStatus ([string]$rules[0].EnforcementStatus))
    ) {
      return $false
    }
    $serviceFilters = @(
      Get-NetFirewallServiceFilter `
        -AssociatedNetFirewallRule $rules[0] `
        -ErrorAction Stop
    )
    return (
      $serviceFilters.Count -eq 1 -and
      $serviceFilters[0].Service -ieq 'wlidsvc'
    )
  } catch {
    return $false
  }
}

function Test-MintServiceBarrierEnforced {
  if (Test-StagingMintServiceRuleEnforced) {
    return $true
  }
  try {
    return [bool](Get-FirewallState).MintServiceRuleValid
  } catch {
    return $false
  }
}

function Wait-StagingMintServiceRuleEnforced {
  param([int]$TimeoutSeconds = 5)

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    if (Test-StagingMintServiceRuleEnforced) {
      return $true
    }
    Start-Sleep -Milliseconds 100
  } while ((Get-Date) -lt $deadline)
  return $false
}

function Wait-PermanentMintServiceRuleEnforced {
  param([int]$TimeoutSeconds = 5)

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    try {
      if ([bool](Get-FirewallState).MintServiceRuleValid) {
        return $true
      }
    } catch {
      Write-Verbose ('Permanent mint-rule check: {0}' -f $_.Exception.Message)
    }
    Start-Sleep -Milliseconds 100
  } while ((Get-Date) -lt $deadline)
  return $false
}

function Remove-DegdidDynamicKeyword {
  param([string]$HostName)

  $id = Get-DynamicKeywordId $HostName
  $existing = @(
    Get-NetFirewallDynamicKeywordAddress `
      -Id $id `
      -ErrorAction SilentlyContinue
  )
  if ($existing.Count -gt 0) {
    Remove-NetFirewallDynamicKeywordAddress `
      -Id $id `
      -Confirm:$false `
      -ErrorAction Stop
  }
}

function Set-FirewallBlock {
  param([switch]$DryRun)

  if (-not (Test-DynamicFirewallSupport)) {
    return [pscustomobject]@{
      Success = $false
      DryRun = [bool]$DryRun
      Message = 'Dynamic-keyword firewall cmdlets are unavailable.'
      State = Get-FirewallState
    }
  }

  if ($DryRun) {
    return [pscustomobject]@{
      Success = $true
      DryRun = $true
      Message = 'Would replace managed keywords and the outbound FQDN rule.'
      State = Get-FirewallState
    }
  }

  try {
    $existingState = Get-FirewallState
    $preserveMintService = [bool]$existingState.MintServiceRuleValid
    Remove-StagingMintServiceRule
    Remove-ManagedFirewallRules `
      -PreserveMintServiceRule:$preserveMintService
    foreach ($hostName in $script:BlockHosts) {
      Remove-DegdidDynamicKeyword -HostName $hostName
    }

    $ids = New-Object System.Collections.Generic.List[string]
    foreach ($hostName in $script:BlockHosts) {
      $id = Get-DynamicKeywordId $hostName
      New-NetFirewallDynamicKeywordAddress `
        -Id $id `
        -Keyword $hostName `
        -AutoResolve $true `
        -ErrorAction Stop | Out-Null
      [void]$ids.Add($id)
    }

    New-NetFirewallRule `
      -Name $script:FirewallRuleName `
      -DisplayName $script:FirewallRuleDisplayName `
      -Group $script:FirewallGroup `
      -Description 'degdid managed FQDN registration block' `
      -Direction Outbound `
      -Action Block `
      -Enabled True `
      -Profile Any `
      -Protocol Any `
      -RemoteDynamicKeywordAddresses $ids.ToArray() `
      -ErrorAction Stop | Out-Null

    if (-not $preserveMintService) {
      New-NetFirewallRule `
        -Name $script:MintServiceRuleName `
        -DisplayName $script:MintServiceRuleDisplayName `
        -Group $script:FirewallGroup `
        -Description 'degdid blocks all wlidsvc outbound DeviceAdd traffic' `
        -Direction Outbound `
        -Action Block `
        -Enabled True `
        -Profile Any `
        -Protocol Any `
        -Program (Join-Path $env:SystemRoot 'System32\svchost.exe') `
        -Service 'wlidsvc' `
        -ErrorAction Stop | Out-Null
    }

    # Hosts entries intentionally suppress normal DNS. Generate explicit
    # no-hosts DNS traffic so the FQDN callout can hydrate the mint keyword
    # when a resolver is reachable. The service rule remains the independent
    # fail-closed mint control when offline or unhydrated.
    foreach ($recordType in @('A', 'AAAA')) {
      Resolve-DnsName `
        -Name $script:MintHost `
        -Type $recordType `
        -DnsOnly `
        -NoHostsFile `
        -QuickTimeout `
        -ErrorAction SilentlyContinue | Out-Null
    }
    if (-not (Wait-PermanentMintServiceRuleEnforced)) {
      throw 'The supplemental wlidsvc rule was created but is not actively enforced.'
    }
  } catch {
    return [pscustomobject]@{
      Success = $false
      DryRun = $false
      Message = $_.Exception.Message
      State = Get-FirewallState
    }
  }

  $state = Get-FirewallState
  return [pscustomobject]@{
    Success = [bool]$state.MintServiceRuleValid
    DryRun = $false
    Message = 'Supplemental firewall configuration refreshed.'
    State = $state
  }
}

function Remove-FirewallBlock {
  param([switch]$DryRun)

  if ($DryRun) {
    return [pscustomobject]@{
      Success = Test-DynamicFirewallSupport
      DryRun = $true
      Message = 'Would remove current managed firewall rules and keywords.'
      State = Get-FirewallState
    }
  }

  try {
    if (
      -not (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) -or
      -not (Get-Command Remove-NetFirewallRule -ErrorAction SilentlyContinue)
    ) {
      throw 'Firewall rule cmdlets are unavailable.'
    }
    Remove-ManagedFirewallRules
    Remove-StagingMintServiceRule

    if (-not (Test-DynamicFirewallSupport)) {
      throw 'Dynamic-keyword cmdlets are unavailable; keyword cleanup cannot verify.'
    }
    foreach ($hostName in $script:BlockHosts) {
      Remove-DegdidDynamicKeyword -HostName $hostName
    }
  } catch {
    return [pscustomobject]@{
      Success = $false
      DryRun = $false
      Message = $_.Exception.Message
      State = Get-FirewallState
    }
  }

  $state = Get-FirewallState
  return [pscustomobject]@{
    Success = $state.Health -eq 'Absent'
    DryRun = $false
    Message = 'Managed firewall rules and keywords removed.'
    State = $state
  }
}

function Test-LooksOnline {
  try {
    $upAdapters = @(
      Get-NetAdapter -ErrorAction Stop |
        Where-Object { $_.Status -eq 'Up' }
    )
    if ($upAdapters.Count -eq 0) {
      return $false
    }
    # Any live adapter is treated as potentially online. This intentionally
    # runs the real TCP probe for VPN, proxy, on-link, and unusual route states
    # instead of misclassifying them as safely offline.
    return $true
  } catch {
    throw 'Network adapter state could not be established: {0}' -f
      $_.Exception.Message
  }
}

function Test-TcpConnect {
  param(
    [string]$HostName,
    [int]$Port = 443,
    [int]$TimeoutMilliseconds = 3000
  )

  $client = [System.Net.Sockets.TcpClient]::new()
  $waitHandle = $null
  try {
    $async = $client.BeginConnect($HostName, $Port, $null, $null)
    $waitHandle = $async.AsyncWaitHandle
    if (-not $waitHandle.WaitOne($TimeoutMilliseconds, $false)) {
      return $false
    }
    $client.EndConnect($async)
    return $client.Connected
  } catch {
    return $false
  } finally {
    if ($null -ne $waitHandle) {
      $waitHandle.Close()
    }
    $client.Close()
  }
}

function Get-MintPathState {
  param(
    [object]$HostsState,
    [object]$FirewallState
  )

  $online = Test-LooksOnline
  $ipv4 = @()
  $ipv6 = @()
  $resolutionErrors = New-Object System.Collections.Generic.List[string]

  try {
    $ipv4 = @(
      Resolve-DnsName `
        -Name $script:MintHost `
        -Type A `
        -ErrorAction Stop |
        Where-Object { $_.IPAddress } |
        ForEach-Object { $_.IPAddress }
    )
  } catch {
    [void]$resolutionErrors.Add(('IPv4: {0}' -f $_.Exception.Message))
  }

  try {
    $ipv6 = @(
      Resolve-DnsName `
        -Name $script:MintHost `
        -Type AAAA `
        -ErrorAction Stop |
        Where-Object { $_.IPAddress } |
        ForEach-Object { $_.IPAddress }
    )
  } catch {
    [void]$resolutionErrors.Add(('IPv6: {0}' -f $_.Exception.Message))
  }

  $ipv4Blocked = (
    $ipv4.Count -gt 0 -and
    @($ipv4 | Where-Object { $_ -ne '0.0.0.0' }).Count -eq 0
  )
  $ipv6Blocked = (
    $ipv6.Count -gt 0 -and
    @($ipv6 | Where-Object { $_ -notin @('::', '0:0:0:0:0:0:0:0') }).Count -eq 0
  )

  $configurationValid = (
    $HostsState.State -eq 'Valid' -and
    $HostsState.Canonical
  )
  $tcpProbe = 'SkippedConfigurationDegraded'
  $tcpBlocked = $false

  if ($configurationValid -and $ipv4Blocked -and $ipv6Blocked) {
    if ($online) {
      $tcpBlocked = -not (Test-TcpConnect -HostName $script:MintHost)
      if ($tcpBlocked) {
        $tcpProbe = 'Blocked'
      } else {
        $tcpProbe = 'Connected'
      }
    } else {
      $tcpBlocked = $true
      $tcpProbe = 'OfflineAccepted'
    }
  }

  $health = 'Degraded'
  if (
    $configurationValid -and
    $ipv4Blocked -and
    $ipv6Blocked -and
    $tcpBlocked
  ) {
    $health = 'Valid'
  } elseif ($resolutionErrors.Count -gt 0 -and $configurationValid) {
    $health = 'Error'
  }

  return [pscustomobject]@{
    Health = $health
    Online = $online
    IPv4Blocked = $ipv4Blocked
    IPv6Blocked = $ipv6Blocked
    IPv4AnswerCount = $ipv4.Count
    IPv6AnswerCount = $ipv6.Count
    UnexpectedAddressCount = @(
      $ipv4 | Where-Object { $_ -ne '0.0.0.0' }
    ).Count + @(
      $ipv6 | Where-Object { $_ -notin @('::', '0:0:0:0:0:0:0:0') }
    ).Count
    TcpProbe = $tcpProbe
    TcpBlocked = $tcpBlocked
    OfflineAccepted = $tcpProbe -eq 'OfflineAccepted'
    Errors = $resolutionErrors.ToArray()
  }
}

function Get-ProtectionGate {
  try {
    $document = Read-HostsDocument
    $hostsState = $document.State
  } catch {
    $hostsState = [pscustomobject]@{
      State = 'Error'
      Canonical = $false
      IPv4Count = 0
      IPv6Count = 0
      MissingIPv4 = @($script:BlockHosts)
      MissingIPv6 = @($script:BlockHosts)
      Error = $_.Exception.Message
    }
  }
  $firewallState = Get-FirewallState
  $mintPath = Get-MintPathState -HostsState $hostsState -FirewallState $firewallState

  return [pscustomobject]@{
    Healthy = (
      $hostsState.State -eq 'Valid' -and
      $hostsState.Canonical -and
      $mintPath.Health -eq 'Valid'
    )
    Hosts = $hostsState
    Firewall = $firewallState
    MintPath = $mintPath
  }
}

function Test-IsAdministrator {
  try {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole(
      [System.Security.Principal.WindowsBuiltInRole]::Administrator
    )
  } catch {
    return $false
  }
}

function Get-DsregJoinState {
  $exe = Join-Path $env:SystemRoot 'System32\dsregcmd.exe'
  if (-not [System.IO.File]::Exists($exe)) {
    return [pscustomobject]@{
      Known = $false
      EntraJoined = $false
      Error = 'dsregcmd.exe is unavailable.'
    }
  }

  try {
    $output = @(& $exe /status 2>&1)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
      throw 'dsregcmd exited with code {0}.' -f $exitCode
    }
    $text = $output -join "`n"
    $azure = [regex]::Match(
      $text,
      '(?im)^\s*AzureAdJoined\s*:\s*(YES|NO)\s*$'
    )
    $enterprise = [regex]::Match(
      $text,
      '(?im)^\s*EnterpriseJoined\s*:\s*(YES|NO)\s*$'
    )
    if (-not $azure.Success -or -not $enterprise.Success) {
      throw 'dsregcmd output did not contain explicit machine join fields.'
    }
    $joined = (
      $azure.Groups[1].Value -eq 'YES' -or
      $enterprise.Groups[1].Value -eq 'YES'
    )
    return [pscustomobject]@{
      Known = $true
      EntraJoined = [bool]$joined
      Error = $null
    }
  } catch {
    return [pscustomobject]@{
      Known = $false
      EntraJoined = $false
      Error = $_.Exception.Message
    }
  }
}

function Get-MdmEnrollmentState {
  $evidence = 0
  try {
    $enrollmentsPath = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments'
    if (Test-Path -LiteralPath $enrollmentsPath -ErrorAction Stop) {
      foreach (
        $key in @(
          Get-ChildItem -LiteralPath $enrollmentsPath -ErrorAction Stop |
            Where-Object {
              $_.PSChildName -match '^\{?[0-9A-Fa-f-]{36}\}?$'
            }
        )
      ) {
        $item = Get-Item -LiteralPath $key.PSPath -ErrorAction Stop
        $names = @($item.GetValueNames())
        $upn = $item.GetValue('UPN', $null)
        $discovery = $item.GetValue('DiscoveryServiceFullURL', $null)
        $state = $item.GetValue('EnrollmentState', $null)
        if (
          $names -contains 'EnrollmentState' -and
          [int]$state -eq 1 -and
          ($upn -or $discovery)
        ) {
          $evidence++
        }
      }
    }

    $omadmPath = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts'
    if (Test-Path -LiteralPath $omadmPath -ErrorAction Stop) {
      $evidence += @(
        Get-ChildItem -LiteralPath $omadmPath -ErrorAction Stop
      ).Count
    }

    return [pscustomobject]@{
      Known = $true
      Enrolled = $evidence -gt 0
      EvidenceCount = $evidence
      Error = $null
    }
  } catch {
    return [pscustomobject]@{
      Known = $false
      Enrolled = $false
      EvidenceCount = $evidence
      Error = $_.Exception.Message
    }
  }
}

function Get-ProfileTopology {
  param([object[]]$Profiles)

  $all = @($Profiles)
  $loaded = @($all | Where-Object { [bool]$_.Loaded })
  return [pscustomobject]@{
    Artifacts = $all
    Loaded = $loaded
    ArtifactCount = $all.Count
    LoadedCount = $loaded.Count
    DormantCount = $all.Count - $loaded.Count
  }
}

function Get-TargetExplorerSessionCount {
  param([string]$TargetSid)

  $sessionIds = New-Object System.Collections.Generic.List[int]
  $ownerErrors = New-Object System.Collections.Generic.List[string]
  foreach (
    $process in @(
      Get-CimInstance Win32_Process `
        -Filter "Name='explorer.exe'" `
        -ErrorAction Stop
    )
  ) {
    try {
      $owner = Invoke-CimMethod `
        -InputObject $process `
        -MethodName GetOwnerSid `
        -ErrorAction Stop
      if (
        $owner.ReturnValue -eq 0 -and
        $owner.Sid -eq $TargetSid -and
        -not $sessionIds.Contains([int]$process.SessionId)
      ) {
        [void]$sessionIds.Add([int]$process.SessionId)
      } elseif ($owner.ReturnValue -ne 0) {
        [void]$ownerErrors.Add(
          'GetOwnerSid returned {0} for Explorer session {1}.' -f
          $owner.ReturnValue,
          $process.SessionId
        )
      }
    } catch {
      [void]$ownerErrors.Add($_.Exception.Message)
    }
  }
  if ($ownerErrors.Count -gt 0) {
    throw 'One or more Explorer session owners could not be inspected: {0}' -f
      ($ownerErrors -join '; ')
  }
  return $sessionIds.Count
}

function Get-EnvironmentState {
  $unsupported = New-Object System.Collections.Generic.List[string]
  $warnings = New-Object System.Collections.Generic.List[string]
  $targetFailures = New-Object System.Collections.Generic.List[string]
  $inspectionErrors = New-Object System.Collections.Generic.List[string]
  $target = $null
  $build = 0
  $displayVersion = $null
  $productName = $null
  $domainJoined = $false
  $humanProfiles = @()
  $loadedHumanProfiles = @()
  $workstation = $false

  if (
    [Environment]::Is64BitOperatingSystem -and
    -not [Environment]::Is64BitProcess
  ) {
    [void]$unsupported.Add(
      'Mutation requires 64-bit PowerShell so the native HKLM identity stores are visible.'
    )
  }

  try {
    $currentVersion = Get-ItemProperty `
      -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
      -ErrorAction Stop
    $build = [int]$currentVersion.CurrentBuildNumber
    $displayVersion = [string]$currentVersion.DisplayVersion
    $productName = [string]$currentVersion.ProductName
    if (-not (Test-SupportedWindowsBuild -Build $build)) {
      [void]$unsupported.Add((
        'Windows 10 22H2 build 19045 or Windows 11 build 22000 or newer is required; found {0} build {1}.' -f
        $displayVersion,
        $build
      ))
    } elseif (
      $build -ne $script:LabValidatedBuild -or
      $displayVersion -ne $script:LabValidatedDisplayVersion
    ) {
      [void]$warnings.Add(
        'This Windows build is supported generically but is not the lab-validated Windows 11 25H2 build 26200 line.'
      )
    }
  } catch {
    [void]$inspectionErrors.Add(('Windows version: {0}' -f $_.Exception.Message))
    [void]$unsupported.Add('Windows version could not be established.')
  }

  try {
    $operatingSystem = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $workstation = [int]$operatingSystem.ProductType -eq 1
    if (-not $workstation) {
      [void]$unsupported.Add('Windows client/workstation edition is required.')
    }
  } catch {
    [void]$inspectionErrors.Add(('Operating system role: {0}' -f $_.Exception.Message))
    [void]$unsupported.Add('Windows workstation role could not be established.')
  }

  $computer = $null
  try {
    $computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $domainJoined = [bool]$computer.PartOfDomain
    if ($domainJoined) {
      [void]$unsupported.Add('Domain-joined systems are outside the mutation contract.')
    }
  } catch {
    [void]$inspectionErrors.Add(('Computer state: {0}' -f $_.Exception.Message))
    [void]$unsupported.Add('Domain-join state could not be established.')
  }

  $dsreg = Get-DsregJoinState
  if (-not $dsreg.Known) {
    [void]$inspectionErrors.Add(('Entra state: {0}' -f $dsreg.Error))
    [void]$unsupported.Add('Entra-join state could not be established.')
  } elseif ($dsreg.EntraJoined) {
    [void]$unsupported.Add('Entra-joined or Entra-registered systems are unsupported.')
  }

  $mdm = Get-MdmEnrollmentState
  if (-not $mdm.Known) {
    [void]$inspectionErrors.Add(('MDM state: {0}' -f $mdm.Error))
    [void]$unsupported.Add('MDM enrollment state could not be established.')
  } elseif ($mdm.Enrolled) {
    [void]$unsupported.Add('MDM-enrolled systems are unsupported.')
  }

  try {
    $humanProfiles = @(
      Get-CimInstance Win32_UserProfile -ErrorAction Stop |
        Where-Object {
          -not $_.Special -and
          $_.LocalPath -and
          $_.SID -match '^S-1-5-21-\d+-\d+-\d+-\d+$'
        }
    )
    $profileTopology = Get-ProfileTopology -Profiles $humanProfiles
    $loadedHumanProfiles = @($profileTopology.Loaded)
    if ($loadedHumanProfiles.Count -gt 1) {
      [void]$unsupported.Add(
        'Only one loaded human-profile hive is supported; found {0}.' -f
        $loadedHumanProfiles.Count
      )
    }
    $dormantCount = $profileTopology.DormantCount
    if ($dormantCount -gt 0) {
      [void]$warnings.Add(
        '{0} dormant non-special profile artifact(s) will not be mutated.' -f
        $dormantCount
      )
    }
  } catch {
    [void]$inspectionErrors.Add(('Profiles: {0}' -f $_.Exception.Message))
    [void]$targetFailures.Add('Human profiles could not be enumerated.')
  }

  $accountName = $null
  $targetResolution = 'InteractiveConsole'
  if ($null -ne $computer) {
    $accountName = [string]$computer.UserName
  }
  if (-not $accountName -and $loadedHumanProfiles.Count -eq 1) {
    try {
      $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
      if (
        $currentIdentity.User.Value -eq $loadedHumanProfiles[0].SID
      ) {
        $accountName = $currentIdentity.Name
        $targetResolution = 'AuthenticatedSoleProfile'
      }
    } catch {
      [void]$inspectionErrors.Add(
        ('Authenticated-profile fallback: {0}' -f $_.Exception.Message)
      )
    }
  }
  if (-not $accountName) {
    [void]$targetFailures.Add(
      'No active interactive user or authenticated sole-profile session was available.'
    )
  } else {
    try {
      $account = [System.Security.Principal.NTAccount]::new($accountName)
      $sid = $account.Translate(
        [System.Security.Principal.SecurityIdentifier]
      ).Value
      $profile = @($humanProfiles | Where-Object { $_.SID -eq $sid })
      if ($profile.Count -ne 1) {
        [void]$targetFailures.Add(
          'The active/authenticated target does not map to one profile artifact.'
        )
      } else {
        $hivePath = 'Registry::HKEY_USERS\{0}' -f $sid
        $hiveLoaded = (
          [bool]$profile[0].Loaded -and
          (Test-Path -LiteralPath $hivePath -ErrorAction Stop)
        )
        if (-not $hiveLoaded) {
          [void]$targetFailures.Add('The active target user hive is not loaded.')
        }
        $interactiveSessionCount = -1
        try {
          $interactiveSessionCount = Get-TargetExplorerSessionCount -TargetSid $sid
          if (
            $targetResolution -eq 'InteractiveConsole' -and
            $interactiveSessionCount -ne 1
          ) {
            [void]$warnings.Add(
              'Target user has {0} Explorer session(s); interactive credential cleanup requires exactly one.' -f
              $interactiveSessionCount
            )
          }
        } catch {
          [void]$inspectionErrors.Add(
            ('Interactive sessions: {0}' -f $_.Exception.Message)
          )
        }
        $target = [pscustomobject]@{
          AccountName = $accountName
          Sid = $sid
          ProfilePath = [string]$profile[0].LocalPath
          HivePath = $hivePath
          HiveLoaded = $hiveLoaded
          Resolution = $targetResolution
          InteractiveSessionCount = $interactiveSessionCount
        }
        if ($hiveLoaded) {
          $workplacePath = (
            '{0}\Software\Microsoft\Windows NT\CurrentVersion\WorkplaceJoin\JoinInfo' -f
            $hivePath
          )
          if (
            (Test-Path -LiteralPath $workplacePath -ErrorAction Stop) -and
            @(Get-ChildItem -LiteralPath $workplacePath -ErrorAction Stop).Count -gt 0
          ) {
            [void]$unsupported.Add(
              'The target user has a Workplace/Entra registration and is unsupported.'
            )
          }
        }
      }
    } catch {
      [void]$inspectionErrors.Add(('Target user: {0}' -f $_.Exception.Message))
      [void]$targetFailures.Add('The active interactive user SID could not be resolved.')
    }
  }

  return [pscustomobject]@{
    Supported = ($unsupported.Count -eq 0 -and $targetFailures.Count -eq 0)
    IsAdministrator = Test-IsAdministrator
    IsWindows11 = ($build -ge 22000 -and $workstation)
    IsWindows10 = (
      $build -ge 10240 -and
      $build -lt 22000 -and
      $workstation
    )
    IsSupportedBuild = (
      (Test-SupportedWindowsBuild -Build $build) -and
      $workstation
    )
    IsLabValidatedBuild = (
      $build -eq $script:LabValidatedBuild -and
      $displayVersion -eq $script:LabValidatedDisplayVersion -and
      $workstation
    )
    Is64BitProcess = [Environment]::Is64BitProcess
    Unmanaged = (
      $dsreg.Known -and
      $mdm.Known -and
      -not $domainJoined -and
      -not $dsreg.EntraJoined -and
      -not $mdm.Enrolled
    )
    Build = $build
    DisplayVersion = $displayVersion
    ProductName = $productName
    DomainJoined = $domainJoined
    EntraJoined = [bool]$dsreg.EntraJoined
    MdmEnrolled = [bool]$mdm.Enrolled
    HumanProfileCount = $loadedHumanProfiles.Count
    DormantProfileCount = $humanProfiles.Count - $loadedHumanProfiles.Count
    ProfileArtifactCount = $humanProfiles.Count
    Target = $target
    Warnings = $warnings.ToArray()
    UnsupportedReasons = $unsupported.ToArray()
    TargetFailureReasons = $targetFailures.ToArray()
    InspectionErrors = $inspectionErrors.ToArray()
  }
}

function Get-MutationPreflight {
  param([object]$Environment)

  if ($Environment.TargetFailureReasons.Count -gt 0 -or $null -eq $Environment.Target) {
    return [pscustomobject]@{
      Allowed = $false
      ExitCode = 6
      Message = ($Environment.TargetFailureReasons -join ' ')
    }
  }
  if ($Environment.UnsupportedReasons.Count -gt 0) {
    return [pscustomobject]@{
      Allowed = $false
      ExitCode = 2
      Message = ($Environment.UnsupportedReasons -join ' ')
    }
  }
  if (-not $Environment.IsAdministrator) {
    return [pscustomobject]@{
      Allowed = $false
      ExitCode = 1
      Message = 'Mutating actions require an elevated administrator PowerShell.'
    }
  }
  return [pscustomobject]@{
    Allowed = $true
    ExitCode = 0
    Message = 'Mutation environment accepted.'
  }
}

function Get-TargetLocalAppData {
  param([object]$Target)

  $fallback = Join-Path $Target.ProfilePath 'AppData\Local'
  $shellFoldersPath = (
    '{0}\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -f
    $Target.HivePath
  )

  try {
    if (-not (Test-Path -LiteralPath $shellFoldersPath -ErrorAction Stop)) {
      return [pscustomobject]@{
        Path = $fallback
        Error = $null
      }
    }

    $key = Get-Item -LiteralPath $shellFoldersPath -ErrorAction Stop
    $raw = [string]$key.GetValue(
      'Local AppData',
      $null,
      [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
    )
    if (-not $raw) {
      return [pscustomobject]@{
        Path = $fallback
        Error = $null
      }
    }

    $expanded = [regex]::Replace(
      $raw,
      '(?i)%USERPROFILE%',
      [System.Text.RegularExpressions.MatchEvaluator]{
        param($match)
        return $Target.ProfilePath
      }
    )
    $expanded = [regex]::Replace(
      $expanded,
      '(?i)%HOMEDRIVE%%HOMEPATH%',
      [System.Text.RegularExpressions.MatchEvaluator]{
        param($match)
        return $Target.ProfilePath
      }
    )
    $systemDrive = [System.IO.Path]::GetPathRoot(
      $Target.ProfilePath
    ).TrimEnd('\')
    $expanded = [regex]::Replace(
      $expanded,
      '(?i)%SystemDrive%',
      [System.Text.RegularExpressions.MatchEvaluator]{
        param($match)
        return $systemDrive
      }
    )
    if ($expanded -match '%[^%]+%') {
      throw 'Local AppData contains an unsupported environment variable.'
    }

    return [pscustomobject]@{
      Path = $expanded
      Error = $null
    }
  } catch {
    return [pscustomobject]@{
      Path = $fallback
      Error = 'Target Local AppData: {0}' -f $_.Exception.Message
    }
  }
}

function Get-DeviceCredentialState {
  param([string[]]$Targets = $script:DeviceCredentialTargets)

  $cmdkey = Join-Path $env:SystemRoot 'System32\cmdkey.exe'
  $output = @(& $cmdkey /list 2>&1)
  if ($LASTEXITCODE -ne 0) {
    throw "cmdkey /list exited with code $LASTEXITCODE"
  }
  $text = $output -join "`n"
  return @(
    foreach ($targetName in $Targets) {
      [pscustomobject]@{
        Target = $targetName
        Present = $text.IndexOf(
          $targetName,
          [System.StringComparison]::OrdinalIgnoreCase
        ) -ge 0
      }
    }
  )
}

function Remove-DeviceCredential {
  param([string]$TargetName)

  $cmdkey = Join-Path $env:SystemRoot 'System32\cmdkey.exe'
  & $cmdkey ("/delete:{0}" -f $TargetName) 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "cmdkey could not remove device credential $TargetName"
  }
  $remaining = @(
    Get-DeviceCredentialState -Targets @($TargetName) |
      Where-Object { $_.Present }
  )
  if ($remaining.Count -gt 0) {
    throw "Device credential $TargetName is still present after deletion."
  }
}

function Get-TargetCredentialAccessMode {
  param([object]$Target)

  $currentSid = (
    [System.Security.Principal.WindowsIdentity]::GetCurrent()
  ).User.Value
  if ($Target.Resolution -eq 'InteractiveConsole') {
    if ($Target.InteractiveSessionCount -ne 1) {
      return 'Unavailable'
    }
    if (Test-IsAdministrator) {
      return 'InteractiveTask'
    }
    if ($currentSid -eq $Target.Sid) {
      return 'DirectInteractive'
    }
  }
  if ($Target.Resolution -eq 'AuthenticatedSoleProfile') {
    if ($Target.InteractiveSessionCount -lt 0) {
      return 'Unavailable'
    }
    if (
      $Target.InteractiveSessionCount -eq 0 -and
      $currentSid -eq $Target.Sid
    ) {
      return 'DirectCurrentSession'
    }
    if (
      $Target.InteractiveSessionCount -eq 1 -and
      (Test-IsAdministrator)
    ) {
      return 'InteractiveTask'
    }
    return 'Unavailable'
  }
  if ($currentSid -eq $Target.Sid) {
    return 'DirectCurrentSession'
  }
  return 'Unavailable'
}

function Invoke-CredentialTask {
  param(
    [string]$UserId,
    [ValidateSet('Interactive', 'ServiceAccount')]
    [string]$LogonType,
    [ValidateSet('Limited', 'Highest')]
    [string]$RunLevel,
    [string]$ResultDirectory,
    [string[]]$Targets,
    [ValidateSet('Inspect', 'Delete')]
    [string]$Mode
  )

  $taskName = 'degdid-credential-{0}' -f [Guid]::NewGuid().ToString('N')
  $resultPath = Join-Path $ResultDirectory ('{0}.json' -f $taskName)
  if (Test-Path -LiteralPath $resultPath) {
    Remove-Item -LiteralPath $resultPath -Force -ErrorAction Stop
  }
  $targetLiteral = (
    $Targets |
      ForEach-Object { "'{0}'" -f $_.Replace("'", "''") }
  ) -join ','
  $resultLiteral = $resultPath.Replace("'", "''")
  $deleteLiteral = $(if ($Mode -eq 'Delete') { '$true' } else { '$false' })
  $helper = @"
`$ErrorActionPreference = 'Stop'
`$targets = @($targetLiteral)
`$delete = $deleteLiteral
`$cmdkey = Join-Path `$env:SystemRoot 'System32\cmdkey.exe'
function Get-State {
  `$output = @(& `$cmdkey /list 2>&1)
  if (`$LASTEXITCODE -ne 0) { throw "cmdkey /list failed: `$LASTEXITCODE" }
  `$text = `$output -join "`n"
  @(
    foreach (`$targetName in `$targets) {
      [pscustomobject]@{
        Target = `$targetName
        Present = `$text.IndexOf(
          `$targetName,
          [System.StringComparison]::OrdinalIgnoreCase
        ) -ge 0
      }
    }
  )
}
`$errors = @()
if (`$delete) {
  foreach (`$state in @(Get-State | Where-Object { `$_.Present })) {
    & `$cmdkey ("/delete:{0}" -f `$state.Target) 2>&1 | Out-Null
    if (`$LASTEXITCODE -ne 0) {
      `$errors += "cmdkey delete failed for `$(`$state.Target)"
    }
  }
}
`$result = [pscustomobject]@{
  States = @(Get-State)
  Errors = @(`$errors)
}
[System.IO.File]::WriteAllText(
  '$resultLiteral',
  (`$result | ConvertTo-Json -Depth 4),
  [System.Text.UTF8Encoding]::new(`$false)
)
"@
  $encoded = [Convert]::ToBase64String(
    [System.Text.Encoding]::Unicode.GetBytes($helper)
  )
  $powershell = Join-Path $env:SystemRoot (
    'System32\WindowsPowerShell\v1.0\powershell.exe'
  )
  $action = New-ScheduledTaskAction `
    -Execute $powershell `
    -Argument ('-NoProfile -NonInteractive -EncodedCommand {0}' -f $encoded)
  $principal = New-ScheduledTaskPrincipal `
    -UserId $UserId `
    -LogonType $LogonType `
    -RunLevel $RunLevel

  try {
    Register-ScheduledTask `
      -TaskName $taskName `
      -Action $action `
      -Principal $principal `
      -Force `
      -ErrorAction Stop | Out-Null
    Start-ScheduledTask -TaskName $taskName -ErrorAction Stop
    $deadline = (Get-Date).AddSeconds(30)
    while (
      -not (Test-Path -LiteralPath $resultPath) -and
      (Get-Date) -lt $deadline
    ) {
      Start-Sleep -Milliseconds 200
    }
    if (-not (Test-Path -LiteralPath $resultPath)) {
      $info = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
      throw 'Credential helper produced no result. LastTaskResult={0}' -f
        $(if ($info) { $info.LastTaskResult } else { 'unknown' })
    }
    $result = Get-Content -LiteralPath $resultPath -Raw -ErrorAction Stop |
      ConvertFrom-Json
    if (@($result.Errors).Count -gt 0) {
      throw (@($result.Errors) -join '; ')
    }
    return @($result.States)
  } finally {
    Unregister-ScheduledTask `
      -TaskName $taskName `
      -Confirm:$false `
      -ErrorAction SilentlyContinue
    Remove-Item `
      -LiteralPath $resultPath `
      -Force `
      -ErrorAction SilentlyContinue
  }
}

function Invoke-TargetDeviceCredentialOperation {
  param(
    [object]$Target,
    [string[]]$Targets,
    [ValidateSet('Inspect', 'Delete')]
    [string]$Mode
  )

  $accessMode = Get-TargetCredentialAccessMode -Target $Target
  if ($accessMode -eq 'InteractiveTask') {
    return @(
      Invoke-CredentialTask `
        -UserId $Target.Sid `
        -LogonType Interactive `
        -RunLevel Limited `
        -ResultDirectory (Join-Path $Target.ProfilePath 'AppData\Local\Temp') `
        -Targets $Targets `
        -Mode $Mode
    )
  }
  if ($accessMode -in @('DirectInteractive', 'DirectCurrentSession')) {
    if ($Mode -eq 'Delete') {
      foreach (
        $state in @(
          Get-DeviceCredentialState -Targets $Targets |
            Where-Object { $_.Present }
        )
      ) {
        Remove-DeviceCredential -TargetName $state.Target
      }
    }
    return @(Get-DeviceCredentialState -Targets $Targets)
  }
  throw 'The target interactive Credential Manager session is unavailable.'
}

function Invoke-SystemDeviceCredentialOperation {
  param(
    [string[]]$Targets,
    [ValidateSet('Inspect', 'Delete')]
    [string]$Mode
  )

  if (-not (Test-IsAdministrator)) {
    throw 'SYSTEM Credential Manager inspection requires elevation.'
  }
  return @(
    Invoke-CredentialTask `
      -UserId 'SYSTEM' `
      -LogonType ServiceAccount `
      -RunLevel Highest `
      -ResultDirectory $env:ProgramData `
      -Targets $Targets `
      -Mode $Mode
  )
}

function Get-GdidSourceModel {
  param([object]$Target)

  $localAppDataResult = Get-TargetLocalAppData -Target $Target
  $localAppData = $localAppDataResult.Path
  $identityScopes = @(
    [pscustomobject]@{
      Name = 'TargetUser'
      HivePath = $Target.HivePath
      NativeHivePath = $Target.Sid
    },
    [pscustomobject]@{
      Name = 'Default'
      HivePath = 'Registry::HKEY_USERS\.DEFAULT'
      NativeHivePath = '.DEFAULT'
    },
    [pscustomobject]@{
      Name = 'System'
      HivePath = 'Registry::HKEY_USERS\S-1-5-18'
      NativeHivePath = 'S-1-5-18'
    }
  )

  return [pscustomobject]@{
    Target = $Target
    ProfilePath = $Target.ProfilePath
    Errors = @($localAppDataResult.Error | Where-Object { $_ })
    IdentityScopes = $identityScopes
    Lids = @(
      foreach ($scope in $identityScopes) {
        [pscustomobject]@{
          Name = '{0}Lid' -f $scope.Name
          Scope = $scope.Name
          Path = (
            '{0}\SOFTWARE\Microsoft\IdentityCRL\ExtendedProperties' -f
            $scope.HivePath
          )
        }
      }
    )
    Properties = @(
      foreach ($scope in $identityScopes) {
        [pscustomobject]@{
          Name = '{0}Property' -f $scope.Name
          Scope = $scope.Name
          Path = (
            '{0}\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Property' -f
            $scope.HivePath
          )
          NativePath = (
            '{0}\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Property' -f
            $scope.NativeHivePath
          )
        }
      }
    )
    Tokens = @(
      foreach ($scope in $identityScopes) {
        [pscustomobject]@{
          Name = '{0}Token' -f $scope.Name
          Scope = $scope.Name
          Path = (
            '{0}\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Token' -f
            $scope.HivePath
          )
        }
      }
    )
    DeviceIdentityPaths = @(
      [pscustomobject]@{
        Name = 'DefaultDeviceIdentityProduction'
        Path = (
          'Registry::HKEY_USERS\.DEFAULT\Software\Microsoft\IdentityCRL\DeviceIdentities\production'
        )
      },
      [pscustomobject]@{
        Name = 'SystemDeviceIdentityProduction'
        Path = (
          'Registry::HKEY_USERS\S-1-5-18\Software\Microsoft\IdentityCRL\DeviceIdentities\production'
        )
      }
    )
    NegativeCachePath = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\IdentityCRL\NegativeCache'
    CredentialAccessMode = Get-TargetCredentialAccessMode -Target $Target
    CredentialTargets = @($script:DeviceCredentialTargets)
    SystemCredentialAccessSupported = Test-IsAdministrator
    SystemCredentialTargets = @($script:DeviceCredentialTargets)
    CachePaths = @(
      [pscustomobject]@{
        Name = 'TokenBroker'
        Path = Join-Path $localAppData 'Microsoft\TokenBroker\Cache'
      },
      [pscustomobject]@{
        Name = 'ConnectedDevicesPlatform'
        Path = Join-Path $localAppData 'ConnectedDevicesPlatform'
      }
    )
  }
}

function Test-GdidSourceModelSafety {
  param([object]$Model)

  $errors = New-Object System.Collections.Generic.List[string]
  try {
    $profileRoot = [System.IO.Path]::GetFullPath($Model.ProfilePath).TrimEnd('\')
    $profilePrefix = $profileRoot + '\'
    if (-not [System.IO.Directory]::Exists($profileRoot)) {
      [void]$errors.Add('Target profile root does not exist.')
    } else {
      $profileItem = [System.IO.DirectoryInfo]::new($profileRoot)
      if (
        ($profileItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
      ) {
        [void]$errors.Add('Target profile root is a reparse point.')
      }
    }

    foreach ($cachePath in $Model.CachePaths) {
      $fullPath = [System.IO.Path]::GetFullPath($cachePath.Path)
      if (
        -not $fullPath.StartsWith(
          $profilePrefix,
          [System.StringComparison]::OrdinalIgnoreCase
        )
      ) {
        [void]$errors.Add(
          '{0} cache is outside the target profile.' -f $cachePath.Name
        )
        continue
      }

      # Reject a junction/symlink in any existing component between the
      # target profile and the cache root, not merely at the final directory.
      $errorCountBeforePath = $errors.Count
      $cursor = $fullPath.TrimEnd('\')
      while (
        $cursor.Length -ge $profileRoot.Length -and
        $cursor.StartsWith(
          $profileRoot,
          [System.StringComparison]::OrdinalIgnoreCase
        )
      ) {
        if ([System.IO.Directory]::Exists($cursor)) {
          $cursorItem = [System.IO.DirectoryInfo]::new($cursor)
          if (
            ($cursorItem.Attributes -band
              [System.IO.FileAttributes]::ReparsePoint) -ne 0
          ) {
            [void]$errors.Add((
              '{0} cache path contains reparse component {1}.' -f
              $cachePath.Name,
              $cursorItem.Name
            ))
            break
          }
        }
        if ($cursor -ieq $profileRoot) {
          break
        }
        $parent = [System.IO.Path]::GetDirectoryName($cursor)
        if (-not $parent -or $parent -eq $cursor) {
          break
        }
        $cursor = $parent.TrimEnd('\')
      }
      if ($errors.Count -gt $errorCountBeforePath) {
        continue
      }

      if (-not (Test-Path -LiteralPath $fullPath -ErrorAction Stop)) {
        continue
      }

      $root = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
      if (
        ([System.IO.FileAttributes]$root.Attributes -band
          [System.IO.FileAttributes]::ReparsePoint) -ne 0
      ) {
        [void]$errors.Add(
          '{0} cache root is a reparse point.' -f $cachePath.Name
        )
        continue
      }

      $pending = [System.Collections.Stack]::new()
      $pending.Push([System.IO.DirectoryInfo]$root)
      while ($pending.Count -gt 0) {
        $directory = [System.IO.DirectoryInfo]$pending.Pop()
        foreach ($child in $directory.GetFileSystemInfos()) {
          if (
            ($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
          ) {
            [void]$errors.Add(
              '{0} cache contains a reparse point.' -f $cachePath.Name
            )
            continue
          }
          if ($child -is [System.IO.DirectoryInfo]) {
            $pending.Push($child)
          }
        }
      }
    }
  } catch {
    [void]$errors.Add(('Cache path safety: {0}' -f $_.Exception.Message))
  }

  return [pscustomobject]@{
    Success = $errors.Count -eq 0
    Errors = $errors.ToArray()
  }
}

function Add-InventoryEntry {
  param(
    [System.Collections.Generic.List[object]]$Entries,
    [string]$Category,
    [string]$SourceKind,
    [string]$Source,
    [string]$Identifier
  )

  if ($null -eq $Identifier -or [string]$Identifier -eq '') {
    return
  }
  [void]$Entries.Add([pscustomobject]@{
    Category = $Category
    SourceKind = $SourceKind
    Source = $Source
    RawIdentifier = [string]$Identifier
    IsReal = Test-RealPuid ([string]$Identifier)
  })
}

function Get-GdidLocationLabel {
  param([object]$Entry)

  if ($Entry.SourceKind -eq 'Lid') {
    if ($Entry.Source -eq 'TargetUserLid') { return 'current user LID' }
    if ($Entry.Source -eq 'DefaultLid') { return 'default-profile machine LID' }
    if ($Entry.Source -eq 'SystemLid') { return 'SYSTEM machine LID' }
    return 'LID store'
  }
  if ($Entry.SourceKind -eq 'ImmersiveProperty') {
    if ($Entry.Source -eq 'TargetUserProperty') {
      return 'current user Immersive Property'
    }
    if ($Entry.Source -eq 'DefaultProperty') {
      return 'default-profile machine Immersive Property'
    }
    if ($Entry.Source -eq 'SystemProperty') {
      return 'SYSTEM machine Immersive Property'
    }
    return 'Immersive Property'
  }
  if ($Entry.SourceKind -eq 'TokenDeviceId') {
    if ($Entry.Source -like 'TargetUserToken:*') {
      return 'current user device-token copy'
    }
    if ($Entry.Source -like 'DefaultToken:*') {
      return 'default-profile machine device-token copy'
    }
    if ($Entry.Source -like 'SystemToken:*') {
      return 'SYSTEM machine device-token copy'
    }
    return 'device-token copy'
  }
  if ($Entry.SourceKind -eq 'NegativeCache') {
    return 'machine NegativeCache'
  }
  return [string]$Entry.SourceKind
}

function Get-GdidInventory {
  param([object]$Model)

  $entries = New-Object System.Collections.Generic.List[object]
  $errors = New-Object System.Collections.Generic.List[string]
  $propertyValues = New-Object System.Collections.Generic.List[object]
  $tokenKeys = New-Object System.Collections.Generic.List[object]
  $deviceIdentityArtifacts = New-Object System.Collections.Generic.List[object]
  $negativeCacheKeys = New-Object System.Collections.Generic.List[object]
  $cacheArtifacts = New-Object System.Collections.Generic.List[object]
  $deviceCredentials = New-Object System.Collections.Generic.List[object]
  foreach ($modelError in $Model.Errors) {
    [void]$errors.Add($modelError)
  }

  foreach ($lidSource in $Model.Lids) {
    try {
      if (Test-Path -LiteralPath $lidSource.Path -ErrorAction Stop) {
        $key = Get-Item -LiteralPath $lidSource.Path -ErrorAction Stop
        $value = $key.GetValue(
          'LID',
          $null,
          [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        )
        if ($null -ne $value) {
          Add-InventoryEntry `
            -Entries $entries `
            -Category 'Active' `
            -SourceKind 'Lid' `
            -Source $lidSource.Name `
            -Identifier ([string]$value)
        }
      }
    } catch {
      [void]$errors.Add(('{0}: {1}' -f $lidSource.Name, $_.Exception.Message))
    }
  }

  foreach ($propertySource in $Model.Properties) {
    try {
      if (Test-Path -LiteralPath $propertySource.Path -ErrorAction Stop) {
        $key = Get-Item -LiteralPath $propertySource.Path -ErrorAction Stop
        foreach ($name in @($key.GetValueNames())) {
          [void]$propertyValues.Add([pscustomobject]@{
            Name = $name
            Scope = $propertySource.Scope
            Path = $propertySource.Path
            NativePath = $propertySource.NativePath
          })
          Add-InventoryEntry `
            -Entries $entries `
            -Category 'Active' `
            -SourceKind 'ImmersiveProperty' `
            -Source $propertySource.Name `
            -Identifier $name
        }
      }
    } catch {
      [void]$errors.Add((
        '{0}: {1}' -f $propertySource.Name, $_.Exception.Message
      ))
    }
  }

  foreach ($tokenSource in $Model.Tokens) {
    try {
      if (Test-Path -LiteralPath $tokenSource.Path -ErrorAction Stop) {
        foreach (
          $tokenKey in @(
            Get-ChildItem -LiteralPath $tokenSource.Path -ErrorAction Stop
          )
        ) {
          $item = Get-Item -LiteralPath $tokenKey.PSPath -ErrorAction Stop
          $valueNames = @($item.GetValueNames())
          [void]$tokenKeys.Add([pscustomobject]@{
            Path = $tokenKey.PSPath
            Name = $tokenKey.PSChildName
            Scope = $tokenSource.Scope
            HasDeviceId = $valueNames -contains 'DeviceId'
            HasDeviceTicket = $valueNames -contains 'DeviceTicket'
          })
          if ($valueNames -contains 'DeviceId') {
            $deviceId = $item.GetValue(
              'DeviceId',
              $null,
              [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
            )
            if ($null -ne $deviceId) {
              Add-InventoryEntry `
                -Entries $entries `
                -Category 'Active' `
                -SourceKind 'TokenDeviceId' `
                -Source ('{0}Token:{1}' -f $tokenSource.Scope, $tokenKey.PSChildName) `
                -Identifier ([string]$deviceId)
            }
          }
        }
      }
    } catch {
      [void]$errors.Add((
        '{0}: {1}' -f $tokenSource.Name, $_.Exception.Message
      ))
    }
  }

  foreach ($deviceIdentityPath in $Model.DeviceIdentityPaths) {
    try {
      if (
        Test-Path -LiteralPath $deviceIdentityPath.Path -ErrorAction Stop
      ) {
        [void]$deviceIdentityArtifacts.Add($deviceIdentityPath)
      }
    } catch {
      [void]$errors.Add((
        '{0}: {1}' -f $deviceIdentityPath.Name, $_.Exception.Message
      ))
    }
  }

  try {
    if (Test-Path -LiteralPath $Model.NegativeCachePath -ErrorAction Stop) {
      foreach (
        $cacheKey in @(
          Get-ChildItem -LiteralPath $Model.NegativeCachePath -ErrorAction Stop
        )
      ) {
        $puids = @(Get-EmbeddedRealPuids $cacheKey.PSChildName)
        if ($puids.Count -gt 0) {
          [void]$negativeCacheKeys.Add([pscustomobject]@{
            Path = $cacheKey.PSPath
            Name = $cacheKey.PSChildName
            Puids = $puids
          })
          foreach ($puid in $puids) {
            Add-InventoryEntry `
              -Entries $entries `
              -Category 'ResidualCache' `
              -SourceKind 'NegativeCache' `
              -Source 'MachineNegativeCache' `
              -Identifier $puid
          }
        }
      }
    }
  } catch {
    [void]$errors.Add(('MachineNegativeCache: {0}' -f $_.Exception.Message))
  }

  foreach ($cachePath in $Model.CachePaths) {
    try {
      $count = 0
      if (Test-Path -LiteralPath $cachePath.Path -ErrorAction Stop) {
        $count = @(
          Get-ChildItem -LiteralPath $cachePath.Path -Force -ErrorAction Stop
        ).Count
      }
      [void]$cacheArtifacts.Add([pscustomobject]@{
        Name = $cachePath.Name
        Count = $count
        Present = $count -gt 0
      })
    } catch {
      [void]$errors.Add(('{0}Cache: {1}' -f $cachePath.Name, $_.Exception.Message))
    }
  }

  $targetCredentialInspectionAvailable = $false
  $systemCredentialInspectionAvailable = $false
  if ($Model.CredentialAccessMode -ne 'Unavailable') {
    try {
      foreach (
        $credentialState in @(
          Invoke-TargetDeviceCredentialOperation `
            -Target $Model.Target `
            -Targets $Model.CredentialTargets `
            -Mode Inspect
        )
      ) {
        [void]$deviceCredentials.Add([pscustomobject]@{
          Scope = 'TargetUser'
          Target = $credentialState.Target
          Present = [bool]$credentialState.Present
        })
      }
      $targetCredentialInspectionAvailable = $true
    } catch {
      [void]$errors.Add(('TargetUserDeviceCredentials: {0}' -f $_.Exception.Message))
    }
  }
  if ($Model.SystemCredentialAccessSupported) {
    try {
      foreach (
        $credentialState in @(
          Invoke-SystemDeviceCredentialOperation `
            -Targets $Model.SystemCredentialTargets `
            -Mode Inspect
        )
      ) {
        [void]$deviceCredentials.Add([pscustomobject]@{
          Scope = 'SYSTEM'
          Target = $credentialState.Target
          Present = [bool]$credentialState.Present
        })
      }
      $systemCredentialInspectionAvailable = $true
    } catch {
      [void]$errors.Add(('SystemDeviceCredentials: {0}' -f $_.Exception.Message))
    }
  }

  $activeReal = @(
    $entries |
      Where-Object { $_.Category -eq 'Active' -and $_.IsReal } |
      ForEach-Object { $_.RawIdentifier.ToUpperInvariant() } |
      Select-Object -Unique
  )
  $residualReal = @(
    $entries |
      Where-Object { $_.Category -eq 'ResidualCache' -and $_.IsReal } |
      ForEach-Object { $_.RawIdentifier.ToUpperInvariant() } |
      Select-Object -Unique
  )
  $allReal = @($activeReal + $residualReal | Select-Object -Unique)

  return [pscustomobject]@{
    Entries = $entries.ToArray()
    Errors = $errors.ToArray()
    PropertyValues = $propertyValues.ToArray()
    TokenKeys = $tokenKeys.ToArray()
    DeviceIdentityArtifacts = $deviceIdentityArtifacts.ToArray()
    NegativeCacheKeys = $negativeCacheKeys.ToArray()
    CacheArtifacts = $cacheArtifacts.ToArray()
    CredentialInspectionAvailable = (
      $targetCredentialInspectionAvailable -and
      $systemCredentialInspectionAvailable
    )
    TargetCredentialInspectionAvailable = $targetCredentialInspectionAvailable
    SystemCredentialInspectionAvailable = $systemCredentialInspectionAvailable
    DeviceCredentials = $deviceCredentials.ToArray()
    ActiveRealPuids = $activeReal
    ResidualRealPuids = $residualReal
    AllRealPuids = $allReal
  }
}

function Get-GdidServiceSnapshot {
  try {
    $services = @(
      Get-Service -ErrorAction Stop |
        Where-Object {
          $_.Name -match '^(wlidsvc|CDPSvc|TokenBroker|CDPUserSvc.*)$'
        } |
        Sort-Object Name
    )
    $unstable = @(
      $services |
        Where-Object { $_.Status -notin @('Running', 'Stopped') }
    )
    if ($unstable.Count -gt 0) {
      throw 'Identity services are in transitional/paused states: {0}' -f (
        ($unstable | ForEach-Object { '{0}={1}' -f $_.Name, $_.Status }) -join ','
      )
    }
    return [pscustomobject]@{
      Success = $true
      Error = $null
      Services = @(
        $services | ForEach-Object {
          [pscustomobject]@{
            Name = $_.Name
            WasRunning = $_.Status -eq 'Running'
            StartType = [string]$_.StartType
            TemporarilyDisabled = $false
          }
        }
      )
    }
  } catch {
    return [pscustomobject]@{
      Success = $false
      Error = $_.Exception.Message
      Services = @()
    }
  }
}

function Add-OperationResult {
  param(
    [System.Collections.Generic.List[object]]$Results,
    [string]$OperationName,
    [scriptblock]$Action,
    [switch]$DryRun
  )

  if ($DryRun) {
    [void]$Results.Add([pscustomobject]@{
      Name = $OperationName
      Success = $true
      Planned = $true
      Error = $null
    })
    return $true
  }

  try {
    & $Action | Out-Null
    [void]$Results.Add([pscustomobject]@{
      Name = $OperationName
      Success = $true
      Planned = $false
      Error = $null
    })
    return $true
  } catch {
    [void]$Results.Add([pscustomobject]@{
      Name = $OperationName
      Success = $false
      Planned = $false
      Error = $_.Exception.Message
    })
    return $false
  }
}

function Restore-GdidServiceStartType {
  param([object]$State)

  if (-not $State.TemporarilyDisabled) {
    return
  }
  $startupType = switch ($State.StartType) {
    'Automatic' { 'Automatic' }
    'Manual' { 'Manual' }
    'Disabled' { 'Disabled' }
    default {
      throw 'Unsupported original startup type {0} for {1}.' -f
        $State.StartType,
        $State.Name
    }
  }
  Set-Service `
    -Name $State.Name `
    -StartupType $startupType `
    -ErrorAction Stop
  $State.TemporarilyDisabled = $false
}

function Wait-GdidServiceStopped {
  param(
    [string]$Name,
    [int]$TimeoutSeconds
  )

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    $service = Get-Service -Name $Name -ErrorAction Stop
    if ($service.Status -eq 'Stopped') {
      return $true
    }
    Start-Sleep -Milliseconds 250
  } while ((Get-Date) -lt $deadline)
  return $false
}

function Invoke-GdidScStop {
  param([string]$Name)

  $sc = Join-Path $env:SystemRoot 'System32\sc.exe'
  return @(& $sc stop $Name 2>&1)
}

function Stop-GdidServiceRobust {
  param([object]$State)

  $service = Get-Service -Name $State.Name -ErrorAction Stop
  if ($service.Status -eq 'Stopped') {
    return
  }

  $firstError = $null
  try {
    Stop-Service -Name $State.Name -Force -ErrorAction Stop
  } catch {
    $firstError = $_.Exception.Message
  }
  if (Wait-GdidServiceStopped -Name $State.Name -TimeoutSeconds 20) {
    return
  }

  if ($State.Name -ne 'wlidsvc') {
    throw 'Service {0} did not stop within 20 seconds. Initial error: {1}' -f
      $State.Name,
      $firstError
  }

  # MSA-heavy systems can immediately trigger-start wlidsvc while it is being
  # stopped. Disable only this service temporarily, retry via SCM, and restore
  # its original startup type before normal service resumption.
  try {
    Set-Service -Name $State.Name -StartupType Disabled -ErrorAction Stop
    $State.TemporarilyDisabled = $true
    $scOutput = @(Invoke-GdidScStop -Name $State.Name)
    if (
      -not (Wait-GdidServiceStopped -Name $State.Name -TimeoutSeconds 30)
    ) {
      throw 'SCM stop timed out. sc.exe: {0}; initial Stop-Service: {1}' -f
        ($scOutput -join ' '),
        $firstError
    }
  } catch {
    if ($State.TemporarilyDisabled) {
      try {
        Restore-GdidServiceStartType -State $State
      } catch {
        Write-Warning (
          'Failed to restore {0} startup type after stop failure: {1}' -f
          $State.Name,
          $_.Exception.Message
        )
      }
    }
    throw
  }
}

function Stop-GdidServices {
  param(
    [object[]]$ServiceStates,
    [System.Collections.Generic.List[object]]$Results,
    [switch]$DryRun
  )

  $success = $true
  foreach ($state in $ServiceStates | Where-Object { $_.WasRunning }) {
    $name = $state.Name
    $ok = Add-OperationResult `
      -Results $Results `
      -OperationName ('StopService:{0}' -f $name) `
      -DryRun:$DryRun `
      -Action {
        Stop-GdidServiceRobust -State $state
      }
    if (-not $ok) {
      $success = $false
    }
  }
  return $success
}

function Stop-AllGdidServices {
  param(
    [object[]]$ServiceStates,
    [System.Collections.Generic.List[object]]$Results
  )

  $success = $true
  foreach ($state in $ServiceStates) {
    $name = $state.Name
    $ok = Add-OperationResult `
      -Results $Results `
      -OperationName ('FailClosedStopService:{0}' -f $name) `
      -Action {
        Stop-GdidServiceRobust -State $state
      }
    if (-not $ok) {
      $success = $false
    }
  }
  return $success
}

function Set-FailClosedMintBarrier {
  param(
    [object[]]$ServiceStates,
    [System.Collections.Generic.List[object]]$Results
  )

  $stageOk = Add-OperationResult `
    -Results $Results `
    -OperationName 'EnsureFailClosedMintServiceRule' `
    -Action {
      New-StagingMintServiceRule
      if (-not (Test-MintServiceBarrierEnforced)) {
        throw 'Neither the permanent nor staging wlidsvc deny is enforced.'
      }
    }
  $servicesStopped = Stop-AllGdidServices `
    -ServiceStates $ServiceStates `
    -Results $Results
  return ($stageOk -and $servicesStopped)
}

function Resume-GdidServices {
  param(
    [object[]]$ServiceStates,
    [System.Collections.Generic.List[object]]$Results,
    [switch]$DryRun
  )

  $success = $true
  foreach ($state in $ServiceStates | Where-Object { $_.WasRunning }) {
    $name = $state.Name
    $ok = Add-OperationResult `
      -Results $Results `
      -OperationName ('ResumeService:{0}' -f $name) `
      -DryRun:$DryRun `
      -Action {
        Restore-GdidServiceStartType -State $state
        $service = Get-Service -Name $name -ErrorAction Stop
        if ($service.Status -ne 'Running') {
          Start-Service -Name $name -ErrorAction Stop
          $service = Get-Service -Name $name -ErrorAction Stop
          $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(15))
        }
      }
    if (-not $ok) {
      $success = $false
    }
  }
  return $success
}

function Start-GdidSettleServices {
  param(
    [object[]]$ServiceStates,
    [System.Collections.Generic.List[object]]$Results
  )

  $temporaryNames = New-Object System.Collections.Generic.List[string]
  $success = $true
  foreach (
    $state in $ServiceStates |
      Where-Object { -not $_.WasRunning -and $_.StartType -ne 'Disabled' }
  ) {
    $name = $state.Name
    $ok = Add-OperationResult `
      -Results $Results `
      -OperationName ('SettleStartService:{0}' -f $name) `
      -Action {
        $service = Get-Service -Name $name -ErrorAction Stop
        if ($service.Status -ne 'Running') {
          Start-Service -Name $name -ErrorAction Stop
        }
      }
    if ($ok) {
      [void]$temporaryNames.Add($name)
    } else {
      $success = $false
    }
  }

  return [pscustomobject]@{
    Success = $success
    TemporaryNames = $temporaryNames.ToArray()
  }
}

function Stop-GdidSettleServices {
  param(
    [string[]]$ServiceNames,
    [System.Collections.Generic.List[object]]$Results
  )

  $success = $true
  foreach ($name in $ServiceNames) {
    $serviceName = $name
    $ok = Add-OperationResult `
      -Results $Results `
      -OperationName ('SettleRestoreService:{0}' -f $serviceName) `
      -Action {
        $service = Get-Service -Name $serviceName -ErrorAction Stop
        if ($service.Status -ne 'Stopped') {
          Stop-Service -Name $serviceName -Force -ErrorAction Stop
          $service = Get-Service -Name $serviceName -ErrorAction Stop
          $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
        }
      }
    if (-not $ok) {
      $success = $false
    }
  }
  return $success
}

function Test-GdidServiceRestoration {
  param(
    [object[]]$ServiceStates,
    [System.Collections.Generic.List[object]]$Results
  )

  $success = $true
  foreach ($state in $ServiceStates) {
    $name = $state.Name
    $expected = $(if ($state.WasRunning) { 'Running' } else { 'Stopped' })
    $ok = Add-OperationResult `
      -Results $Results `
      -OperationName ('VerifyServiceState:{0}' -f $name) `
      -Action {
        $service = Get-Service -Name $name -ErrorAction Stop
        if ($service.Status.ToString() -ne $expected) {
          throw 'Expected {0}; observed {1}.' -f $expected, $service.Status
        }
      }
    if (-not $ok) {
      $success = $false
    }
  }
  return $success
}

function Invoke-IdentityStoreChanges {
  param(
    [object]$Model,
    [object]$Before,
    [string[]]$CapturedPuids,
    [ValidateSet('Wipe', 'Decoy')]
    [string]$Mode,
    [AllowNull()][string]$DecoyLid,
    [System.Collections.Generic.List[object]]$Results,
    [switch]$DryRun
  )

  foreach ($propertyValue in $Before.PropertyValues) {
    $name = $propertyValue.Name
    $nativePath = $propertyValue.NativePath
    $scopeName = $propertyValue.Scope
    [void](Add-OperationResult `
      -Results $Results `
      -OperationName (
        'ClearProperty:{0}:{1}' -f
        $scopeName,
        (Get-Sha256Hex $name).Substring(0, 8)
      ) `
      -DryRun:$DryRun `
      -Action {
        $propertyKey = [Microsoft.Win32.Registry]::Users.OpenSubKey(
          $nativePath,
          $true
        )
        if (-not $propertyKey) {
          throw 'Target-user Immersive Property key could not be opened writable.'
        }
        try {
          $propertyKey.DeleteValue($name, $false)
        } finally {
          $propertyKey.Close()
        }
      })
  }

  foreach ($tokenKey in $Before.TokenKeys) {
    $path = $tokenKey.Path
    $tokenName = $tokenKey.Name
    [void](Add-OperationResult `
      -Results $Results `
      -OperationName ('ClearToken:{0}' -f (Get-Sha256Hex $tokenName).Substring(0, 8)) `
      -DryRun:$DryRun `
      -Action {
        $key = Get-Item -LiteralPath $path -ErrorAction Stop
        $valueNames = @($key.GetValueNames())
        if ($valueNames -contains 'DeviceTicket') {
          Remove-ItemProperty `
            -LiteralPath $path `
            -Name 'DeviceTicket' `
            -ErrorAction Stop
        }
        if ($valueNames -contains 'DeviceId') {
          Remove-ItemProperty `
            -LiteralPath $path `
            -Name 'DeviceId' `
            -ErrorAction Stop
        }
        if ($Mode -eq 'Decoy' -and $tokenKey.HasDeviceId) {
          New-ItemProperty `
            -LiteralPath $path `
            -Name 'DeviceId' `
            -Value $DecoyLid `
            -PropertyType String `
            -Force `
            -ErrorAction Stop | Out-Null
        }
      })
  }

  if ($Before.TargetCredentialInspectionAvailable) {
    [void](Add-OperationResult `
      -Results $Results `
      -OperationName 'ClearTargetSessionDeviceCredentials' `
      -DryRun:$DryRun `
      -Action {
        $remaining = @(
          Invoke-TargetDeviceCredentialOperation `
            -Target $Model.Target `
            -Targets $Model.CredentialTargets `
            -Mode Delete |
            Where-Object { $_.Present }
        )
        if ($remaining.Count -gt 0) {
          throw 'One or more target-session device credentials remain.'
        }
      })
  }
  if ($Before.SystemCredentialInspectionAvailable) {
    [void](Add-OperationResult `
      -Results $Results `
      -OperationName 'ClearSystemSessionDeviceCredentials' `
      -DryRun:$DryRun `
      -Action {
        $remaining = @(
          Invoke-SystemDeviceCredentialOperation `
            -Targets $Model.SystemCredentialTargets `
            -Mode Delete |
            Where-Object { $_.Present }
        )
        if ($remaining.Count -gt 0) {
          throw 'One or more SYSTEM-session device credentials remain.'
        }
      })
  }

  foreach ($deviceIdentity in $Before.DeviceIdentityArtifacts) {
    $path = $deviceIdentity.Path
    $name = $deviceIdentity.Name
    [void](Add-OperationResult `
      -Results $Results `
      -OperationName ('ClearDeviceIdentity:{0}' -f $name) `
      -DryRun:$DryRun `
      -Action {
        if (Test-Path -LiteralPath $path -ErrorAction Stop) {
          Remove-Item `
            -LiteralPath $path `
            -Recurse `
            -Force `
            -ErrorAction Stop
        }
      })
  }

  foreach ($cacheKey in $Before.NegativeCacheKeys) {
    $matchesCaptured = $false
    foreach ($puid in $cacheKey.Puids) {
      if ($CapturedPuids -contains $puid.ToUpperInvariant()) {
        $matchesCaptured = $true
        break
      }
    }
    if (-not $matchesCaptured) {
      continue
    }

    $path = $cacheKey.Path
    $cacheName = $cacheKey.Name
    [void](Add-OperationResult `
      -Results $Results `
      -OperationName ('ClearNegativeCache:{0}' -f (Get-Sha256Hex $cacheName).Substring(0, 8)) `
      -DryRun:$DryRun `
      -Action {
        Remove-Item `
          -LiteralPath $path `
          -Recurse `
          -Force `
          -ErrorAction Stop
      })
  }

  foreach ($lidSource in $Model.Lids) {
    $path = $lidSource.Path
    $sourceName = $lidSource.Name
    [void](Add-OperationResult `
      -Results $Results `
      -OperationName ('SetLid:{0}' -f $sourceName) `
      -DryRun:$DryRun `
      -Action {
        if ($Mode -eq 'Wipe') {
          if (Test-Path -LiteralPath $path -ErrorAction Stop) {
            $key = Get-Item -LiteralPath $path -ErrorAction Stop
            if (@($key.GetValueNames()) -contains 'LID') {
              Remove-ItemProperty `
                -LiteralPath $path `
                -Name 'LID' `
                -ErrorAction Stop
            }
          }
        } else {
          if (-not (Test-Path -LiteralPath $path -ErrorAction Stop)) {
            New-Item -Path $path -Force -ErrorAction Stop | Out-Null
          }
          New-ItemProperty `
            -LiteralPath $path `
            -Name 'LID' `
            -Value $DecoyLid `
            -PropertyType String `
            -Force `
            -ErrorAction Stop | Out-Null
        }
      })
  }

  foreach ($cachePath in $Model.CachePaths) {
    $path = $cachePath.Path
    $cacheName = $cachePath.Name
    [void](Add-OperationResult `
      -Results $Results `
      -OperationName ('ClearFiles:{0}' -f $cacheName) `
      -DryRun:$DryRun `
      -Action {
        if (Test-Path -LiteralPath $path -ErrorAction Stop) {
          $root = Get-Item -LiteralPath $path -Force -ErrorAction Stop
          if (
            ($root.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
          ) {
            throw '{0} cache root became a reparse point.' -f $cacheName
          }
          foreach (
            $child in @(
              Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop
            )
          ) {
            if (
              ($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
            ) {
              throw '{0} cache acquired a reparse-point child.' -f $cacheName
            }
            Remove-Item `
              -LiteralPath $child.FullName `
              -Recurse `
              -Force `
              -ErrorAction Stop
          }
        }
      })
  }
}

function Test-WipePostcondition {
  param(
    [object]$Inventory,
    [string[]]$CapturedPuids,
    [ValidateSet('Wipe', 'Decoy')]
    [string]$Mode,
    [AllowNull()][string]$DecoyLid,
    [object]$Model
  )

  $reasons = New-Object System.Collections.Generic.List[string]
  if ($Inventory.Errors.Count -gt 0) {
    [void]$reasons.Add('Post-wait inventory had read errors.')
  }

  $capturedRemaining = @(
    $Inventory.AllRealPuids |
      Where-Object { $CapturedPuids -contains $_.ToUpperInvariant() }
  )
  if ($capturedRemaining.Count -gt 0) {
    [void]$reasons.Add('A captured old PUID remains.')
  }
  if (-not $Inventory.CredentialInspectionAvailable) {
    [void]$reasons.Add('Target-user device credentials could not be inspected.')
  } elseif (
    @($Inventory.DeviceCredentials | Where-Object { $_.Present }).Count -gt 0
  ) {
    [void]$reasons.Add('An MSA device credential remains.')
  }
  if ($Inventory.DeviceIdentityArtifacts.Count -gt 0) {
    [void]$reasons.Add('A machine DeviceIdentities subtree remains.')
  }

  if ($Mode -eq 'Wipe') {
    if (
      @(
        $Inventory.Entries |
          Where-Object {
            $_.Category -eq 'Active' -and
            ($_.SourceKind -eq 'Lid' -or $_.SourceKind -eq 'TokenDeviceId')
          }
      ).Count -gt 0
    ) {
      [void]$reasons.Add('An LID or Token DeviceId value remains.')
    }
    if ($Inventory.PropertyValues.Count -gt 0) {
      [void]$reasons.Add('Immersive Property values remain.')
    }
    if (@($Inventory.TokenKeys | Where-Object { $_.HasDeviceTicket }).Count -gt 0) {
      [void]$reasons.Add('A Token DeviceTicket remains.')
    }
    if ($Inventory.ActiveRealPuids.Count -gt 0) {
      [void]$reasons.Add('A real-shaped PUID exists in an active store.')
    }
    if ($Inventory.ResidualRealPuids.Count -gt 0) {
      [void]$reasons.Add('A real-shaped PUID exists in a residual registry cache.')
    }
  } else {
    $activeEntries = @(
      $Inventory.Entries | Where-Object { $_.Category -eq 'Active' }
    )
    $identityEntries = @(
      $activeEntries |
        Where-Object {
          $_.SourceKind -eq 'Lid' -or
          $_.SourceKind -eq 'TokenDeviceId' -or
          ($_.SourceKind -eq 'ImmersiveProperty' -and $_.IsReal)
        }
    )
    if (
      $identityEntries.Count -eq 0 -or
      @(
        $identityEntries |
          Where-Object { $_.RawIdentifier -ine $DecoyLid }
      ).Count -gt 0
    ) {
      [void]$reasons.Add('Active identifiers are not consistently the generated decoy.')
    }
    foreach ($lidSource in $Model.Lids) {
      $matching = @(
        $activeEntries |
          Where-Object {
            $_.SourceKind -eq 'Lid' -and
            $_.Source -eq $lidSource.Name -and
            $_.RawIdentifier -ieq $DecoyLid
          }
      )
      if ($matching.Count -ne 1) {
        [void]$reasons.Add(('Decoy is missing from {0}.' -f $lidSource.Name))
      }
    }
  }

  return [pscustomobject]@{
    Success = $reasons.Count -eq 0
    Reasons = $reasons.ToArray()
  }
}

function Invoke-IdentityMutation {
  param(
    [ValidateSet('Wipe', 'Decoy')]
    [string]$Mode,
    [object]$Target,
    [switch]$DryRun
  )

  $results = New-Object System.Collections.Generic.List[object]
  $model = Get-GdidSourceModel -Target $Target
  if ($model.Errors.Count -gt 0) {
    return [pscustomobject]@{
      Success = $false
      ExitCode = 5
      Message = 'Target source paths could not be resolved; no mutation was attempted.'
      CapturedCount = 0
      Decoy = $null
      Results = @()
      Postcondition = $null
      Errors = @($model.Errors)
    }
  }
  if ($model.CredentialAccessMode -eq 'Unavailable') {
    return [pscustomobject]@{
      Success = $false
      ExitCode = 6
      Message = 'The target Windows Credential Manager session is unavailable.'
      CapturedCount = 0
      Decoy = $null
      Results = @()
      Postcondition = $null
      Errors = @(
        'No direct or interactive-task credential context could be established; no mutation was attempted.'
      )
    }
  }
  if (-not $model.SystemCredentialAccessSupported) {
    return [pscustomobject]@{
      Success = $false
      ExitCode = 1
      Message = 'SYSTEM Credential Manager inspection requires elevation.'
      CapturedCount = 0
      Decoy = $null
      Results = @()
      Postcondition = $null
      Errors = @('No mutation was attempted.')
    }
  }
  $sourceSafety = Test-GdidSourceModelSafety -Model $model
  if (-not $sourceSafety.Success) {
    return [pscustomobject]@{
      Success = $false
      ExitCode = 5
      Message = 'Target cache paths failed safety validation; no mutation was attempted.'
      CapturedCount = 0
      Decoy = $null
      Results = @()
      Postcondition = $null
      Errors = @($sourceSafety.Errors)
    }
  }
  $before = Get-GdidInventory -Model $model
  if ($before.Errors.Count -gt 0) {
    return [pscustomobject]@{
      Success = $false
      ExitCode = 5
      Message = 'Pre-mutation inventory failed; no identity mutation was attempted.'
      CapturedCount = $before.AllRealPuids.Count
      Decoy = $null
      Results = @()
      Postcondition = $null
      Errors = @($before.Errors)
    }
  }

  $captured = @(
    $before.AllRealPuids |
      ForEach-Object { $_.ToUpperInvariant() } |
      Select-Object -Unique
  )
  $decoy = $null
  if ($Mode -eq 'Decoy') {
    do {
      $decoy = New-DecoyLid
    } while ($captured -contains $decoy)
  }

  if ($DryRun) {
    return [pscustomobject]@{
      Success = $true
      ExitCode = 0
      Message = 'DryRun planned identity mutation; no state was changed.'
      CapturedCount = $captured.Count
      Decoy = $decoy
      Results = @()
      Postcondition = $null
      Errors = @()
    }
  }

  $snapshot = Get-GdidServiceSnapshot
  if (-not $snapshot.Success) {
    return [pscustomobject]@{
      Success = $false
      ExitCode = 5
      Message = 'Identity services could not be inventoried; no mutation was attempted.'
      CapturedCount = $captured.Count
      Decoy = $decoy
      Results = @()
      Postcondition = $null
      Errors = @($snapshot.Error)
    }
  }

  $stopped = Stop-GdidServices -ServiceStates $snapshot.Services -Results $results
  if (-not $stopped) {
    return [pscustomobject]@{
      Success = $false
      ExitCode = 5
      Message = 'Quiescing identity services failed; identity stores were not changed and service state was left fail-closed.'
      CapturedCount = $captured.Count
      Decoy = $decoy
      Results = $results.ToArray()
      Postcondition = $null
      Errors = @(
        $results |
          Where-Object { -not $_.Success } |
          ForEach-Object { '{0}: {1}' -f $_.Name, $_.Error }
      )
    }
  }

  $quiescedInventory = Get-GdidInventory -Model $model
  if ($quiescedInventory.Errors.Count -gt 0) {
    return [pscustomobject]@{
      Success = $false
      ExitCode = 5
      Message = 'Quiesced inventory failed; identity stores were not changed and services remain quiesced.'
      CapturedCount = $captured.Count
      Decoy = $decoy
      Results = $results.ToArray()
      Postcondition = $null
      Errors = @($quiescedInventory.Errors)
    }
  }

  $before = $quiescedInventory
  $captured = @(
    $captured + @(
      $before.AllRealPuids |
        ForEach-Object { $_.ToUpperInvariant() }
    ) | Select-Object -Unique
  )
  if ($Mode -eq 'Decoy') {
    do {
      $decoy = New-DecoyLid
    } while ($captured -contains $decoy)
  }

  $preWriteGate = Get-ProtectionGate
  if (-not $preWriteGate.Healthy) {
    $barrier = Set-FailClosedMintBarrier `
      -ServiceStates $snapshot.Services `
      -Results $results
    return [pscustomobject]@{
      Success = $false
      ExitCode = 3
      Message = 'Block verification failed immediately before identity writes; services remain quiesced.'
      CapturedCount = $captured.Count
      Decoy = $decoy
      Results = $results.ToArray()
      Postcondition = $null
      Errors = @(
        'Identity stores were not changed.',
        $(if (-not $barrier) { 'Fail-closed mint barrier was incomplete.' })
      ) | Where-Object { $_ }
    }
  }

  $preWriteSafety = Test-GdidSourceModelSafety -Model $model
  if (-not $preWriteSafety.Success) {
    $barrier = Set-FailClosedMintBarrier `
      -ServiceStates $snapshot.Services `
      -Results $results
    return [pscustomobject]@{
      Success = $false
      ExitCode = 5
      Message = 'Cache path safety changed before identity writes; services remain quiesced.'
      CapturedCount = $captured.Count
      Decoy = $decoy
      Results = $results.ToArray()
      Postcondition = $null
      Errors = @($preWriteSafety.Errors) + @(
        $(if (-not $barrier) { 'Fail-closed mint barrier was incomplete.' })
      ) | Where-Object { $_ }
    }
  }

  Invoke-IdentityStoreChanges `
    -Model $model `
    -Before $before `
    -CapturedPuids $captured `
    -Mode $Mode `
    -DecoyLid $decoy `
    -Results $results

  $gate = Get-ProtectionGate
  if (-not $gate.Healthy) {
    $barrier = Set-FailClosedMintBarrier `
      -ServiceStates $snapshot.Services `
      -Results $results
    return [pscustomobject]@{
      Success = $false
      ExitCode = 3
      Message = 'Block verification failed before service settle; services remain quiesced.'
      CapturedCount = $captured.Count
      Decoy = $decoy
      Results = $results.ToArray()
      Postcondition = $null
      Errors = @(
        'Registration block gate was lost after identity writes.',
        $(if (-not $barrier) { 'Fail-closed mint barrier was incomplete.' })
      ) | Where-Object { $_ }
    }
  }

  $resumed = Resume-GdidServices -ServiceStates $snapshot.Services -Results $results
  $settle = Start-GdidSettleServices `
    -ServiceStates $snapshot.Services `
    -Results $results
  Start-Sleep -Seconds $script:SettleSeconds
  $postSettleGate = Get-ProtectionGate
  if ($postSettleGate.Healthy) {
    $settleRestored = Stop-GdidSettleServices `
      -ServiceNames $settle.TemporaryNames `
      -Results $results
    $serviceStateRestored = Test-GdidServiceRestoration `
      -ServiceStates $snapshot.Services `
      -Results $results
  } else {
    $settleRestored = Set-FailClosedMintBarrier `
      -ServiceStates $snapshot.Services `
      -Results $results
    $serviceStateRestored = $false
  }

  # The postcondition inventory is deliberately last, after temporary settle
  # services are stopped or the fail-closed quiesce has been re-established.
  $after = Get-GdidInventory -Model $model
  $postcondition = Test-WipePostcondition `
    -Inventory $after `
    -CapturedPuids $captured `
    -Mode $Mode `
    -DecoyLid $decoy `
    -Model $model

  $operationFailures = @($results | Where-Object { -not $_.Success })
  $gateErrors = @()
  if (-not $postSettleGate.Healthy) {
    $gateErrors = @(
      'Registration block gate was lost during settle; identity services were left fail-closed.'
    )
  }
  $success = (
    $resumed -and
    $settle.Success -and
    $settleRestored -and
    $serviceStateRestored -and
    $postSettleGate.Healthy -and
    $operationFailures.Count -eq 0 -and
    $postcondition.Success
  )

  $errors = @(
    $operationFailures |
      ForEach-Object { '{0}: {1}' -f $_.Name, $_.Error }
  ) + @($after.Errors) + @($postcondition.Reasons) + $gateErrors

  return [pscustomobject]@{
    Success = $success
    ExitCode = $(if ($success) {
      0
    } elseif (-not $postSettleGate.Healthy) {
      3
    } else {
      5
    })
    Message = $(if ($success) {
      '{0} completed and passed the post-wait inventory.' -f $Mode
    } elseif (-not $postSettleGate.Healthy) {
      '{0} failed because the block gate was lost; identity services remain quiesced.' -f $Mode
    } else {
      '{0} failed operation accounting or its postcondition.' -f $Mode
    })
    CapturedCount = $captured.Count
    Decoy = $decoy
    Results = $results.ToArray()
    Postcondition = $postcondition
    AfterInventory = $after
    Errors = @($errors | Where-Object { $_ })
  }
}

function Get-GdidVerdict {
  param(
    [bool]$HasError,
    [bool]$EnvironmentSupported,
    [bool]$HasRealGdid,
    [bool]$BlockHealthy
  )

  if ($HasError) {
    return 'Error'
  }
  if (-not $EnvironmentSupported) {
    return 'UnsupportedEnvironment'
  }
  if ($HasRealGdid) {
    return 'RealGdidPresent'
  }
  if (-not $BlockHealthy) {
    return 'BlockDegraded'
  }
  return 'ProtectedNoRealGdid'
}

function Get-StatusHostsState {
  try {
    $document = Read-HostsDocument
    return [pscustomobject]@{
      State = $document.State.State
      Canonical = $document.State.Canonical
      Encoding = $document.EncodingName
      IPv4Count = $document.State.IPv4Count
      IPv6Count = $document.State.IPv6Count
      MissingIPv4 = @($document.State.MissingIPv4)
      MissingIPv6 = @($document.State.MissingIPv6)
      Error = $null
      InternalState = $document.State
    }
  } catch {
    $internal = [pscustomobject]@{
      State = 'Error'
      Canonical = $false
      IPv4Count = 0
      IPv6Count = 0
      MissingIPv4 = @($script:BlockHosts)
      MissingIPv6 = @($script:BlockHosts)
    }
    return [pscustomobject]@{
      State = 'Error'
      Canonical = $false
      Encoding = $null
      IPv4Count = 0
      IPv6Count = 0
      MissingIPv4 = @($script:BlockHosts)
      MissingIPv6 = @($script:BlockHosts)
      Error = $_.Exception.Message
      InternalState = $internal
    }
  }
}

function Get-DegdidStatus {
  $environment = Get-EnvironmentState
  $hosts = Get-StatusHostsState
  $firewall = Get-FirewallState
  $mintPath = Get-MintPathState `
    -HostsState $hosts.InternalState `
    -FirewallState $firewall

  $inventory = $null
  if ($null -ne $environment.Target) {
    $model = Get-GdidSourceModel -Target $environment.Target
    $inventory = Get-GdidInventory -Model $model
  } else {
    $inventory = [pscustomobject]@{
      Entries = @()
      Errors = @()
      CacheArtifacts = @()
      PropertyValues = @()
      TokenKeys = @()
      DeviceIdentityArtifacts = @()
      CredentialInspectionAvailable = $false
      DeviceCredentials = @()
      ActiveRealPuids = @()
      ResidualRealPuids = @()
      AllRealPuids = @()
    }
  }

  $environmentSupported = (
    $environment.UnsupportedReasons.Count -eq 0 -and
    $environment.TargetFailureReasons.Count -eq 0
  )
  $blockHealthy = (
    $hosts.State -eq 'Valid' -and
    $mintPath.Health -eq 'Valid'
  )
  $hasReal = $inventory.AllRealPuids.Count -gt 0
  $deviceTicketCount = @(
    $inventory.TokenKeys | Where-Object { $_.HasDeviceTicket }
  ).Count
  $deviceCredentialCount = @(
    $inventory.DeviceCredentials | Where-Object { $_.Present }
  ).Count
  $deviceIdentityArtifactCount = @(
    $inventory.DeviceIdentityArtifacts
  ).Count
  $unknownActiveIdentityCount = @(
    $inventory.Entries |
      Where-Object { $_.Category -eq 'Active' -and -not $_.IsReal }
  ).Count
  $hasInspectionError = (
    $environment.InspectionErrors.Count -gt 0 -or
    $hosts.State -eq 'Error' -or
    $firewall.Health -eq 'Error' -or
    $mintPath.Health -eq 'Error' -or
    $inventory.Errors.Count -gt 0
  )
  $hasUnresolvedIdentity = (
    $deviceTicketCount -gt 0 -or
    $unknownActiveIdentityCount -gt 0 -or
    $deviceCredentialCount -gt 0 -or
    $deviceIdentityArtifactCount -gt 0 -or
    -not $inventory.CredentialInspectionAvailable
  )
  $hasError = (
    $hasInspectionError -or
    (-not $hasReal -and $hasUnresolvedIdentity)
  )
  $verdict = Get-GdidVerdict `
    -HasError $hasError `
    -EnvironmentSupported $environmentSupported `
    -HasRealGdid $hasReal `
    -BlockHealthy $blockHealthy

  $environmentInspectionErrors = @($environment.InspectionErrors)
  $environmentWarnings = @($environment.Warnings)
  $firewallErrors = @($firewall.Errors)
  $inventoryErrors = @($inventory.Errors)
  $mintPathErrors = @($mintPath.Errors)
  $mintPathReport = [pscustomobject][ordered]@{
    Health = $mintPath.Health
    Online = $mintPath.Online
    IPv4Blocked = $mintPath.IPv4Blocked
    IPv6Blocked = $mintPath.IPv6Blocked
    IPv4AnswerCount = $mintPath.IPv4AnswerCount
    IPv6AnswerCount = $mintPath.IPv6AnswerCount
    UnexpectedAddressCount = $mintPath.UnexpectedAddressCount
    TcpProbe = $mintPath.TcpProbe
    TcpBlocked = $mintPath.TcpBlocked
    OfflineAccepted = $mintPath.OfflineAccepted
    Errors = $mintPathErrors
  }

  $targetReport = [pscustomobject]@{
    Resolved = $null -ne $environment.Target
    Account = '(none)'
    Sid = '(none)'
    Profile = '(none)'
    HiveLoaded = $false
    Resolution = '(none)'
    InteractiveSessionCount = 0
  }
  if ($null -ne $environment.Target) {
    $targetReport = [pscustomobject]@{
      Resolved = $true
      Account = $environment.Target.AccountName
      Sid = $environment.Target.Sid
      Profile = $environment.Target.ProfilePath
      HiveLoaded = [bool]$environment.Target.HiveLoaded
      Resolution = $environment.Target.Resolution
      InteractiveSessionCount = $environment.Target.InteractiveSessionCount
    }
  }

  $activeEntries = @(
    $inventory.Entries |
      Where-Object { $_.Category -eq 'Active' } |
      ForEach-Object {
        [pscustomobject]@{
          Source = $_.Source
          Kind = $_.SourceKind
          IsRealShaped = $_.IsReal
          Identifier = $_.RawIdentifier
          Gdid = $(if ($_.IsReal) {
            ConvertTo-Gdid $_.RawIdentifier
          } else {
            '(not-real-shaped)'
          })
        }
      }
  )
  $residualEntries = @(
    $inventory.Entries |
      Where-Object { $_.Category -eq 'ResidualCache' } |
      ForEach-Object {
        [pscustomobject]@{
          Source = $_.Source
          Kind = $_.SourceKind
          Identifier = $_.RawIdentifier
        }
      }
  )
  $gdidSummary = @(
    foreach ($puid in @($inventory.AllRealPuids | Sort-Object -Unique)) {
      $matchingEntries = @(
        $inventory.Entries |
          Where-Object { $_.RawIdentifier -ieq $puid }
      )
      $locations = @(
        $matchingEntries |
          ForEach-Object { Get-GdidLocationLabel -Entry $_ } |
          Sort-Object -Unique
      )
      [pscustomobject][ordered]@{
        Gdid = ConvertTo-Gdid $puid
        RegistryId = $puid
        Active = @(
          $matchingEntries | Where-Object { $_.Category -eq 'Active' }
        ).Count -gt 0
        Cached = @(
          $matchingEntries | Where-Object { $_.Category -eq 'ResidualCache' }
        ).Count -gt 0
        TokenCopyCount = @(
          $matchingEntries | Where-Object { $_.SourceKind -eq 'TokenDeviceId' }
        ).Count
        Locations = $locations
      }
    }
  )

  return [pscustomobject][ordered]@{
    Timestamp = (Get-Date).ToString('o')
    Environment = [pscustomobject][ordered]@{
      Supported = $environmentSupported
      IsAdministrator = $environment.IsAdministrator
      IsWindows11 = $environment.IsWindows11
      IsWindows10 = $environment.IsWindows10
      IsSupportedBuild = $environment.IsSupportedBuild
      IsLabValidatedBuild = $environment.IsLabValidatedBuild
      Is64BitProcess = $environment.Is64BitProcess
      Unmanaged = $environment.Unmanaged
      ProductName = $environment.ProductName
      Build = $environment.Build
      DisplayVersion = $environment.DisplayVersion
      DomainJoined = $environment.DomainJoined
      EntraJoined = $environment.EntraJoined
      MdmEnrolled = $environment.MdmEnrolled
      HumanProfileCount = $environment.HumanProfileCount
      DormantProfileCount = $environment.DormantProfileCount
      ProfileArtifactCount = $environment.ProfileArtifactCount
      Warnings = $environmentWarnings
      UnsupportedReasons = @($environment.UnsupportedReasons)
      TargetFailureReasons = @($environment.TargetFailureReasons)
      InspectionErrors = $environmentInspectionErrors
    }
    TargetUser = $targetReport
    Gdids = $gdidSummary
    Hosts = [pscustomobject][ordered]@{
      State = $hosts.State
      Canonical = $hosts.Canonical
      Encoding = $hosts.Encoding
      IPv4Count = $hosts.IPv4Count
      IPv6Count = $hosts.IPv6Count
      MissingIPv4 = @($hosts.MissingIPv4)
      MissingIPv6 = @($hosts.MissingIPv6)
      Error = $hosts.Error
    }
    Firewall = [pscustomobject][ordered]@{
      Available = $firewall.Available
      Health = $firewall.Health
      KeywordCount = $firewall.KeywordCount
      MissingKeywords = @($firewall.MissingKeywords)
      InvalidKeywords = @($firewall.InvalidKeywords)
      RuleCount = $firewall.RuleCount
      RuleValid = $firewall.RuleValid
      FqdnRuleEnforcement = $firewall.FqdnRuleEnforcement
      MintServiceRuleCount = $firewall.MintServiceRuleCount
      MintServiceRuleValid = $firewall.MintServiceRuleValid
      MintServiceRuleEnforcement = $firewall.MintServiceRuleEnforcement
      StagingRuleCount = $firewall.StagingRuleCount
      HydratedKeywordCount = $firewall.HydratedKeywordCount
      MintKeywordHydrated = $firewall.MintKeywordHydrated
      InfrastructureHealthy = $firewall.InfrastructureHealthy
      Errors = $firewallErrors
    }
    MintPath = $mintPathReport
    ActiveStoreInventory = [pscustomobject][ordered]@{
      Count = $activeEntries.Count
      RealShapedCount = @($activeEntries | Where-Object { $_.IsRealShaped }).Count
      UnknownIdentityCount = $unknownActiveIdentityCount
      DeviceTicketCount = $deviceTicketCount
      DeviceCredentialCount = $deviceCredentialCount
      DeviceIdentityArtifactCount = $deviceIdentityArtifactCount
      DeviceCredentialInspectionAvailable = (
        [bool]$inventory.CredentialInspectionAvailable
      )
      Entries = $activeEntries
      Errors = $inventoryErrors
    }
    ResidualCaches = [pscustomobject][ordered]@{
      RealPuidCount = $residualEntries.Count
      Entries = $residualEntries
      Files = @($inventory.CacheArtifacts)
    }
    Verdict = $verdict
  }
}

function Write-DegdidStatusHuman {
  param([object]$Report)

  Write-Output ''
  Write-Output ('degdid status — {0}' -f $Report.Timestamp)
  Write-Output ''
  Write-Output 'This PC'
  $windowsName = if ($Report.Environment.IsWindows11) {
    'Windows 11'
  } elseif ($Report.Environment.IsWindows10) {
    'Windows 10'
  } elseif ($Report.Environment.ProductName) {
    $Report.Environment.ProductName
  } else {
    'Windows'
  }
  Write-Output (
    '  {0} {1}, build {2}' -f
    $windowsName,
    $Report.Environment.DisplayVersion,
    $Report.Environment.Build
  )
  if ($Report.TargetUser.Resolved) {
    Write-Output ('  User:    {0}' -f $Report.TargetUser.Account)
    Write-Output ('  SID:     {0}' -f $Report.TargetUser.Sid)
    Write-Output ('  Profile: {0}' -f $Report.TargetUser.Profile)
  } else {
    Write-Output '  User: could not determine the target profile'
  }
  Write-Output (
    '  Supported by this tool: {0}' -f
    $(if ($Report.Environment.Supported) { 'YES' } else { 'NO' })
  )
  if (-not $Report.Environment.IsAdministrator) {
    Write-Output '  Note: Status works here, but changes require PowerShell as Administrator.'
  }
  if ($Report.Environment.DormantProfileCount -gt 0) {
    Write-Output (
      '  Dormant profiles ignored: {0} (not loaded and not active targets)' -f
      $Report.Environment.DormantProfileCount
    )
  }
  if (
    $Report.TargetUser.Resolution -eq 'InteractiveConsole' -and
    $Report.TargetUser.InteractiveSessionCount -ne 1
  ) {
    Write-Output (
      '  Interactive sessions for target: {0} (credential cleanup requires exactly one)' -f
      $Report.TargetUser.InteractiveSessionCount
    )
  }

  $blockActive = (
    $Report.Hosts.State -eq 'Valid' -and
    $Report.Hosts.Canonical -and
    $Report.MintPath.Health -eq 'Valid'
  )
  $blockAbsent = (
    $Report.Hosts.State -eq 'Absent' -and
    $Report.Firewall.Health -eq 'Absent'
  )
  Write-Output ''
  Write-Output 'Registration protection'
  if ($blockActive) {
    Write-Output '  ACTIVE — Windows DeviceAdd is blocked.'
    Write-Output '  login.live.com: blocked on IPv4 and IPv6; TCP connection failed.'
    if ($Report.Firewall.MintServiceRuleValid) {
      Write-Output '  Supplemental wlidsvc firewall rule: enforced'
    } elseif ($Report.Firewall.StagingRuleCount -gt 0) {
      Write-Output '  Supplemental firewall: temporary mint-service rule present'
    } else {
      Write-Output '  Supplemental firewall: not required for this verified hosts/path state'
    }
  } elseif ($blockAbsent) {
    Write-Output '  NOT CONFIGURED — Windows can contact Microsoft and mint another GDID.'
    Write-Output '  Hosts block: absent'
    Write-Output '  Firewall block: absent'
  } else {
    Write-Output '  INCOMPLETE — some protection exists, but it is not safe to rely on.'
    Write-Output ('  Hosts block: {0}' -f $Report.Hosts.State)
    Write-Output ('  Firewall block: {0}' -f $Report.Firewall.Health)
    Write-Output ('  DeviceAdd path: {0}' -f $Report.MintPath.Health)
  }

  Write-Output ''
  Write-Output 'Global Device Identifiers'
  if ($Report.Gdids.Count -eq 0) {
    if (
      $Report.ActiveStoreInventory.DeviceTicketCount -gt 0 -or
      $Report.ActiveStoreInventory.UnknownIdentityCount -gt 0 -or
      $Report.ActiveStoreInventory.DeviceCredentialCount -gt 0 -or
      $Report.ActiveStoreInventory.DeviceIdentityArtifactCount -gt 0 -or
      -not $Report.ActiveStoreInventory.DeviceCredentialInspectionAvailable
    ) {
      Write-Output '  No readable GDID was found, but opaque identity state remains.'
    } else {
      Write-Output '  No real-shaped GDID was found in the known active or cache stores.'
    }
  } else {
    Write-Output (
      '  FOUND {0} distinct real GDID value(s):' -f $Report.Gdids.Count
    )
    foreach ($gdid in $Report.Gdids) {
      $state = if ($gdid.Active -and $gdid.Cached) {
        'ACTIVE + CACHED'
      } elseif ($gdid.Active) {
        'ACTIVE'
      } else {
        'CACHED ONLY'
      }
      Write-Output ''
      Write-Output ('  {0}  [{1}]' -f $gdid.Gdid, $state)
      Write-Output ('    Registry form: {0}' -f $gdid.RegistryId)
      Write-Output ('    Found in: {0}' -f ($gdid.Locations -join ', '))
      if ($gdid.TokenCopyCount -gt 0) {
        Write-Output (
          '    Device-token copies carrying this ID: {0}' -f
          $gdid.TokenCopyCount
        )
      }
    }
  }
  if ($Report.ActiveStoreInventory.DeviceTicketCount -gt 0) {
    Write-Output ''
    Write-Output (
      '  Opaque device tickets still present: {0}' -f
      $Report.ActiveStoreInventory.DeviceTicketCount
    )
  }
  if ($Report.ActiveStoreInventory.DeviceCredentialCount -gt 0) {
    Write-Output (
      '  MSA device credentials that can restore device identity: {0}' -f
      $Report.ActiveStoreInventory.DeviceCredentialCount
    )
  }
  if ($Report.ActiveStoreInventory.DeviceIdentityArtifactCount -gt 0) {
    Write-Output (
      '  Machine DeviceIdentities roots that can restore device identity: {0}' -f
      $Report.ActiveStoreInventory.DeviceIdentityArtifactCount
    )
  }
  if (-not $Report.ActiveStoreInventory.DeviceCredentialInspectionAvailable) {
    Write-Output '  Not every target-user/SYSTEM device credential vault could be inspected.'
  }

  Write-Output ''
  switch ($Report.Verdict) {
    'ProtectedNoRealGdid' {
      Write-Output 'VERDICT: PROTECTED — no real GDID found and DeviceAdd is blocked.'
      Write-Output 'No action is required. Re-run Status after major Windows or firewall changes.'
    }
    'RealGdidPresent' {
      Write-Output 'VERDICT: REAL GDID PRESENT — Windows has identifiers it can use or send.'
      Write-Output 'Recommended action: .\degdid.ps1 -Protect'
    }
    'BlockDegraded' {
      Write-Output 'VERDICT: NO GDID FOUND, BUT REGISTRATION IS NOT SAFELY BLOCKED.'
      Write-Output 'Recommended action: .\degdid.ps1 -Protect'
    }
    'UnsupportedEnvironment' {
      Write-Output 'VERDICT: THIS MACHINE IS OUTSIDE THE SAFE MUTATION RULES.'
      foreach ($reason in $Report.Environment.UnsupportedReasons) {
        Write-Output ('  - {0}' -f $reason)
      }
      foreach ($reason in $Report.Environment.TargetFailureReasons) {
        Write-Output ('  - {0}' -f $reason)
      }
    }
    default {
      Write-Output 'VERDICT: STATUS IS INCOMPLETE — do not assume the machine is clean.'
      foreach ($errorText in $Report.Environment.InspectionErrors) {
        Write-Output ('  - {0}' -f $errorText)
      }
      if ($Report.Hosts.Error) {
        Write-Output ('  - Hosts: {0}' -f $Report.Hosts.Error)
      }
      foreach ($errorText in $Report.Firewall.Errors) {
        Write-Output ('  - Firewall: {0}' -f $errorText)
      }
      foreach ($errorText in $Report.MintPath.Errors) {
        Write-Output ('  - DeviceAdd check: {0}' -f $errorText)
      }
      foreach ($errorText in $Report.ActiveStoreInventory.Errors) {
        Write-Output ('  - Identity inventory: {0}' -f $errorText)
      }
    }
  }
  Write-Output ''
  Write-Output 'For full technical diagnostics: .\degdid.ps1 -Status -Json'
}

function Invoke-DnsFlush {
  $ipconfig = Join-Path $env:SystemRoot 'System32\ipconfig.exe'
  & $ipconfig /flushdns | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw 'ipconfig /flushdns exited with code {0}.' -f $LASTEXITCODE
  }
}

function Invoke-BlockConfiguration {
  param([switch]$DryRun)

  try {
    $hostsResult = Invoke-HostsDocumentChange -Mode Block -DryRun:$DryRun
  } catch {
    return [pscustomobject]@{
      Success = $false
      ExitCode = 4
      Message = $_.Exception.Message
      Hosts = $null
      Firewall = $null
      Gate = $null
    }
  }

  $warnings = New-Object System.Collections.Generic.List[string]
  $firewallResult = Set-FirewallBlock -DryRun:$DryRun
  if (-not $firewallResult.Success) {
    [void]$warnings.Add(
      'Supplemental firewall was not refreshed: {0}' -f $firewallResult.Message
    )
  }

  if ($DryRun) {
    return [pscustomobject]@{
      Success = $true
      ExitCode = 0
      Message = 'DryRun planned the required hosts refresh and optional firewall refresh; current state was not changed.'
      Hosts = $hostsResult
      Firewall = $firewallResult
      Gate = Get-ProtectionGate
    }
  }

  try {
    Invoke-DnsFlush
  } catch {
    [void]$warnings.Add(('DNS flush failed: {0}' -f $_.Exception.Message))
  }

  $gate = Get-ProtectionGate
  return [pscustomobject]@{
    Success = $gate.Healthy
    ExitCode = $(if ($gate.Healthy) { 0 } else { 3 })
    Message = $(if ($gate.Healthy) {
      $suffix = $(if ($warnings.Count -gt 0) {
        ' Warning: {0}' -f ($warnings -join ' ')
      } else {
        ''
      })
      'Canonical hosts and the actual DeviceAdd path verified.{0}' -f $suffix
    } else {
      'DeviceAdd path verification failed. {0}' -f ($warnings -join ' ')
    })
    Hosts = $hostsResult
    Firewall = $firewallResult
    Gate = $gate
  }
}

function Invoke-UnblockConfiguration {
  param([switch]$DryRun)

  # Validate that the managed region can be removed before touching either
  # layer. The real operation removes firewall state first and hosts last so
  # a partial failure leaves the independent hosts block in place.
  try {
    $hostsPreflight = Invoke-HostsDocumentChange -Mode Unblock -DryRun
  } catch {
    return [pscustomobject]@{
      Success = $false
      ExitCode = 4
      Message = $_.Exception.Message
      Hosts = $null
      Firewall = $null
    }
  }

  $firewallResult = Remove-FirewallBlock -DryRun:$DryRun
  if (-not $firewallResult.Success) {
    return [pscustomobject]@{
      Success = $false
      ExitCode = 3
      Message = 'Firewall cleanup failed; the hosts block was left unchanged.'
      Hosts = $hostsPreflight
      Firewall = $firewallResult
    }
  }

  if ($DryRun) {
    return [pscustomobject]@{
      Success = $true
      ExitCode = 0
      Message = 'Would remove managed firewall state first, then the valid hosts region.'
      Hosts = $hostsPreflight
      Firewall = $firewallResult
    }
  }

  try {
    $hostsResult = Invoke-HostsDocumentChange -Mode Unblock
    Invoke-DnsFlush
    $hostsAfter = Read-HostsDocument
    if ($hostsAfter.State.State -ne 'Absent') {
      throw 'Managed hosts region is still present after Unblock.'
    }
  } catch {
    return [pscustomobject]@{
      Success = $false
      ExitCode = 4
      Message = 'Firewall state was removed, but hosts cleanup did not complete: {0}' -f $_.Exception.Message
      Hosts = $hostsPreflight
      Firewall = $firewallResult
    }
  }

  return [pscustomobject]@{
    Success = $true
    ExitCode = 0
    Message = 'Managed firewall state and valid hosts region removed.'
    Hosts = $hostsResult
    Firewall = $firewallResult
  }
}

function Write-MutationResult {
  param([object]$Result)

  Write-Output $Result.Message
  Write-Output ('CapturedRealPuids={0}' -f $Result.CapturedCount)
  if ($Result.Decoy) {
    Write-Output (
      'GeneratedDecoy={0}' -f
      $Result.Decoy
    )
  }
  $failed = @($Result.Results | Where-Object { -not $_.Success })
  Write-Output (
    'Operations Total={0} Failed={1}' -f
    $Result.Results.Count,
    $failed.Count
  )
  foreach ($failure in $failed) {
    Write-Output (
      'OperationFailure {0}: {1}' -f
      $failure.Name,
      $failure.Error
    )
  }
  foreach ($errorText in $Result.Errors) {
    Write-Output (
      'Error: {0}' -f
      $errorText
    )
  }
  if (-not $Result.Success -and $null -ne $Result.AfterInventory) {
    foreach ($puid in @($Result.AfterInventory.AllRealPuids)) {
      $matching = @(
        $Result.AfterInventory.Entries |
          Where-Object { $_.RawIdentifier -ieq $puid }
      )
      $locations = @(
        $matching |
          ForEach-Object { Get-GdidLocationLabel -Entry $_ } |
          Sort-Object -Unique
      )
      Write-Output (
        'Remaining GDID {0} ({1}) in: {2}' -f
        (ConvertTo-Gdid $puid),
        $puid,
        ($locations -join ', ')
      )
    }
    $remainingCredentials = @(
      $Result.AfterInventory.DeviceCredentials |
        Where-Object { $_.Present }
    )
    if ($remainingCredentials.Count -gt 0) {
      Write-Output (
        'Remaining MSA device credentials: {0}' -f
        (($remainingCredentials | ForEach-Object { $_.Target }) -join ', ')
      )
    }
  }
}

function Invoke-DegdidMain {
  if (-not ($Status -or $Wipe -or $Decoy -or $Block -or $Unblock -or $Protect)) {
    $script:Status = $true
  }

  if ($Status) {
    $report = Get-DegdidStatus
    if ($Json) {
      Write-Output ($report | ConvertTo-Json -Depth 8)
    } else {
      Write-DegdidStatusHuman -Report $report
    }
    $script:DegdidExitCode = 0
    return
  }

  # Recovery must remain available if the machine later becomes managed,
  # gains another profile, or has no interactive user. Unblock touches only
  # degdid-owned network state, not identity stores.
  if ($Unblock) {
    if (-not $DryRun -and -not (Test-IsAdministrator)) {
      Write-Output 'Refused: Unblock requires an elevated administrator PowerShell.'
      $script:DegdidExitCode = 1
      return
    }
    $result = Invoke-UnblockConfiguration -DryRun:$DryRun
    Write-Output $result.Message
    if ($DryRun) {
      Write-Output 'DryRun: no hosts or firewall state was changed.'
    } elseif ($result.Success) {
      Write-Output 'Warning: a future DeviceAdd can mint a real GDID.'
    }
    $script:DegdidExitCode = $result.ExitCode
    return
  }

  $environment = Get-EnvironmentState
  $preflight = Get-MutationPreflight -Environment $environment
  if (-not $preflight.Allowed) {
    Write-Output ('Refused: {0}' -f $preflight.Message)
    $script:DegdidExitCode = $preflight.ExitCode
    return
  }

  if ($Block) {
    $result = Invoke-BlockConfiguration -DryRun:$DryRun
    Write-Output $result.Message
    if ($DryRun -and $null -ne $result.Gate) {
      Write-Output (
        'CurrentBlockApplied={0}; planned state was not substituted for current state.' -f
        $result.Gate.Healthy
      )
    }
    $script:DegdidExitCode = $result.ExitCode
    return
  }

  if ($Protect) {
    $blockResult = Invoke-BlockConfiguration -DryRun:$DryRun
    Write-Output ('Protect block phase: {0}' -f $blockResult.Message)
    if (-not $blockResult.Success) {
      Write-Output 'Protect aborted before identity mutation.'
      $script:DegdidExitCode = $blockResult.ExitCode
      return
    }
    if ($DryRun) {
      $modeName = $(if ($UseDecoy) { 'Decoy' } else { 'Wipe' })
      $mutationPlan = Invoke-IdentityMutation `
        -Mode $modeName `
        -Target $environment.Target `
        -DryRun
      Write-Output (
        'DryRun: would require post-apply gate verification, then run {0}; nothing changed.' -f
        $modeName
      )
      Write-MutationResult -Result $mutationPlan
      if ($null -ne $blockResult.Gate) {
        Write-Output (
          'CurrentBlockApplied={0}; this is current state, not the planned result.' -f
          $blockResult.Gate.Healthy
        )
      }
      $script:DegdidExitCode = $mutationPlan.ExitCode
      return
    }

    $mode = $(if ($UseDecoy) { 'Decoy' } else { 'Wipe' })
    $mutation = Invoke-IdentityMutation `
      -Mode $mode `
      -Target $environment.Target
    Write-MutationResult -Result $mutation
    $script:DegdidExitCode = $mutation.ExitCode
    return
  }

  $gate = Get-ProtectionGate
  if (-not $gate.Healthy) {
    Write-Output (
      'Refused: existing hosts/firewall/mint-path gate is not verified. Use -Protect.'
    )
    if ($DryRun) {
      Write-Output 'DryRun: no identity mutation was attempted.'
    }
    $script:DegdidExitCode = 3
    return
  }

  $mode = $(if ($Decoy) { 'Decoy' } else { 'Wipe' })
  $mutation = Invoke-IdentityMutation `
    -Mode $mode `
    -Target $environment.Target `
    -DryRun:$DryRun
  Write-MutationResult -Result $mutation
  $script:DegdidExitCode = $mutation.ExitCode
}

if (-not $InternalNoExit) {
  try {
    Invoke-DegdidMain
  } catch {
    $safeError = $_.Exception.Message
    if ($Json) {
      Write-Output (
        [pscustomobject][ordered]@{
          Timestamp = (Get-Date).ToString('o')
          Verdict = 'Error'
          Error = $safeError
        } | ConvertTo-Json
      )
    } else {
      Write-Output ('Unexpected error: {0}' -f $safeError)
    }
    $script:DegdidExitCode = 1
  }
  exit $script:DegdidExitCode
}
