$repositoryRoot = Split-Path -Parent $PSScriptRoot
$scriptPath = Join-Path $repositoryRoot 'degdid.ps1'
. $scriptPath -InternalNoExit

Describe 'degdid hosts parser' {
  $hosts = @('one.example', 'two.example')
  $canonicalLines = @(Get-CanonicalHostsRegionLines -Hosts $hosts)
  $canonicalText = ($canonicalLines -join "`r`n") + "`r`n"

  It 'detects an absent managed region' {
    $state = Get-HostsDocumentState -Text "127.0.0.1 localhost`r`n" -Hosts $hosts
    $state.State | Should Be 'Absent'
    $state.MissingIPv4.Count | Should Be 2
    $state.MissingIPv6.Count | Should Be 2
  }

  It 'detects a valid canonical region' {
    $state = Get-HostsDocumentState -Text $canonicalText -Hosts $hosts
    $state.State | Should Be 'Valid'
    $state.Canonical | Should Be $true
    $state.IPv4Count | Should Be 2
    $state.IPv6Count | Should Be 2
    $state.MissingIPv4.Count | Should Be 0
    $state.MissingIPv6.Count | Should Be 0
  }

  It 'recognizes a structurally valid but stale legacy region' {
    $text = @(
      $script:MarkerBegin
      '0.0.0.0 one.example'
      ':: one.example'
      '0.0.0.0 two.example'
      $script:MarkerEnd
    ) -join "`n"
    $state = Get-HostsDocumentState -Text $text -Hosts $hosts
    $state.State | Should Be 'Valid'
    $state.Canonical | Should Be $false
    ($state.MissingIPv6 -contains 'two.example') | Should Be $true
  }

  It 'detects duplicate managed markers' {
    $text = $canonicalText + $canonicalText
    $state = Get-HostsDocumentState -Text $text -Hosts $hosts
    $state.State | Should Be 'Duplicate'
  }

  It 'treats marker lookalikes as malformed instead of absent' {
    $text = "  $script:MarkerBegin`r`n$script:MarkerEnd`r`n"
    (Get-HostsDocumentState -Text $text -Hosts $hosts).State |
      Should Be 'Malformed'
  }
}

Describe 'degdid canonical hosts rendering' {
  $hosts = @('one.example', 'two.example')

  It 'renders one IPv4 and IPv6 entry per hostname' {
    $lines = @(Get-CanonicalHostsRegionLines -Hosts $hosts)
    $lines.Count | Should Be 6
    $lines[0] | Should Be $script:MarkerBegin
    $lines[1] | Should Be '0.0.0.0 one.example'
    $lines[2] | Should Be ':: one.example'
    $lines[3] | Should Be '0.0.0.0 two.example'
    $lines[4] | Should Be ':: two.example'
    $lines[5] | Should Be $script:MarkerEnd
  }

  It 'inserts a canonical region while preserving unrelated text and newline style' {
    $before = "127.0.0.1 localhost`n# keep me`n"
    $after = Set-GdidHostsRegionText -Text $before -Hosts $hosts
    $after.StartsWith($before) | Should Be $true
    $firstPair = [regex]::Escape("0.0.0.0 one.example`n:: one.example")
    $secondPair = [regex]::Escape("0.0.0.0 two.example`n:: two.example")
    $after | Should Match $firstPair
    $after | Should Match $secondPair
    $after -match "`r`n" | Should Be $false
  }

  It 'refreshes a valid region without changing unrelated lines' {
    $region = (Get-CanonicalHostsRegionLines -Hosts $hosts) -join "`r`n"
    $text = "before=untouched`r`n$region`r`nafter=untouched`r`n"
    (Set-GdidHostsRegionText -Text $text -Hosts $hosts) | Should Be $text
  }

  It 'upgrades a paired IPv4-only legacy region to canonical dual-stack' {
    $legacy = @(
      'before=untouched'
      $script:MarkerBegin
      '0.0.0.0 one.example'
      '0.0.0.0 two.example'
      $script:MarkerEnd
      'after=untouched'
    ) -join "`r`n"
    $updated = Set-GdidHostsRegionText -Text $legacy -Hosts $hosts
    $state = Get-HostsDocumentState -Text $updated -Hosts $hosts
    $state.State | Should Be 'Valid'
    $state.Canonical | Should Be $true
    $updated | Should Match 'before=untouched'
    $updated | Should Match 'after=untouched'
  }

  It 'removes only a valid region and preserves unrelated lines exactly' {
    $region = (Get-CanonicalHostsRegionLines -Hosts $hosts) -join "`r`n"
    $text = "before=untouched`r`n$region`r`nafter=untouched`r`n"
    $expected = "before=untouched`r`nafter=untouched`r`n"
    (Remove-GdidHostsRegionText -Text $text -Hosts $hosts) | Should Be $expected
  }

  It 'is a no-op when unblock sees no managed region' {
    $text = "127.0.0.1 localhost`r`n# untouched`r`n"
    (Remove-GdidHostsRegionText -Text $text -Hosts $hosts) | Should Be $text
  }

  It 'removes a structurally paired legacy region safely' {
    $legacy = @(
      'before=untouched'
      $script:MarkerBegin
      '0.0.0.0 one.example'
      $script:MarkerEnd
      'after=untouched'
    ) -join "`r`n"
    $expected = "before=untouched`r`nafter=untouched"
    (Remove-GdidHostsRegionText -Text $legacy -Hosts $hosts) |
      Should Be $expected
  }

  It 'refuses to unblock a malformed region' {
    $text = "$script:MarkerBegin`r`n0.0.0.0 one.example`r`n"
    { Remove-GdidHostsRegionText -Text $text -Hosts $hosts } | Should Throw
  }

  It 'refuses to unblock duplicate regions' {
    $region = ((Get-CanonicalHostsRegionLines -Hosts $hosts) -join "`n") + "`n"
    { Remove-GdidHostsRegionText -Text ($region + $region) -Hosts $hosts } |
      Should Throw
  }

  It 'refuses paired markers that enclose non-owned content' {
    $text = @(
      $script:MarkerBegin
      '127.0.0.1 unrelated.example'
      $script:MarkerEnd
    ) -join "`r`n"
    (Get-HostsDocumentState -Text $text -Hosts $hosts).State |
      Should Be 'Malformed'
    { Set-GdidHostsRegionText -Text $text -Hosts $hosts } | Should Throw
    { Remove-GdidHostsRegionText -Text $text -Hosts $hosts } | Should Throw
  }
}

Describe 'degdid hosts encoding preservation' {
  It 'round-trips a UTF-8 BOM while rendering the managed region' {
    $encoding = [System.Text.UTF8Encoding]::new($false, $true)
    $text = "127.0.0.1 localhost`r`n"
    $bytes = [byte[]](
      @(0xEF, 0xBB, 0xBF) + @($encoding.GetBytes($text))
    )
    $decoded = ConvertFrom-HostsBytes -Bytes $bytes
    $updated = Set-GdidHostsRegionText -Text $decoded.Text -Hosts @('one.example')
    $rendered = ConvertTo-HostsBytes `
      -Text $updated `
      -Encoding $decoded.Encoding `
      -Bom $decoded.Bom

    $rendered[0] | Should Be 0xEF
    $rendered[1] | Should Be 0xBB
    $rendered[2] | Should Be 0xBF
    (ConvertFrom-HostsBytes -Bytes $rendered).Text.StartsWith($text) |
      Should Be $true
  }

  It 'recognizes and preserves BOM-less UTF-16LE' {
    $encoding = [System.Text.UnicodeEncoding]::new($false, $false, $true)
    $text = "127.0.0.1 localhost`r`n"
    $bytes = $encoding.GetBytes($text)
    $decoded = ConvertFrom-HostsBytes -Bytes $bytes
    $decoded.EncodingName | Should Be 'utf-16LE-no-bom'
    $rendered = ConvertTo-HostsBytes `
      -Text $decoded.Text `
      -Encoding $decoded.Encoding `
      -Bom $decoded.Bom
    (Test-ByteArrayEqual -Left $bytes -Right $rendered) | Should Be $true
  }
}

Describe 'degdid PUID pure helpers' {
  It 'accepts only a real-shaped device PUID' {
    (Test-RealPuid '0018000FC8CB93CC') | Should Be $true
    (Test-RealPuid '0018abcdef123456') | Should Be $true
    (Test-RealPuid '0003000FC8CB93CC') | Should Be $false
    (Test-RealPuid '0018000FC8CB93C') | Should Be $false
    (Test-RealPuid '0018000FC8CB93CG') | Should Be $false
  }

  It 'converts a 64-bit hexadecimal PUID to the documented GDID form' {
    (ConvertTo-Gdid '0018000FC8CB93CC') | Should Be 'g:6755467234350028'
    (ConvertTo-Gdid 'not-a-puid') | Should Be $null
  }

  It 'redacts a PUID by default with a stable prefix and hash' {
    $redacted = Format-GdidIdentifier '0018000FC8CB93CC'
    $redacted | Should Match '^0018\.\.\.#[0-9a-f]{8}$'
    (Format-GdidIdentifier '0018000FC8CB93CC') | Should Be $redacted
    (Format-GdidIdentifier '0018000FC8CB93CC' -Show) |
      Should Be '0018000FC8CB93CC'
  }

  It 'extracts distinct embedded real PUIDs from cache key names' {
    $found = @(
      Get-EmbeddedRealPuids '0018000FC8CB93CC_scope_0018000fc8cb93cc'
    )
    $found.Count | Should Be 1
    $found[0] | Should Be '0018000FC8CB93CC'
  }
}

Describe 'degdid verdict oracle' {
  It 'returns Error before all other states' {
    (Get-GdidVerdict $true $false $true $false) | Should Be 'Error'
  }

  It 'returns UnsupportedEnvironment for unsupported readable systems' {
    (Get-GdidVerdict $false $false $true $false) |
      Should Be 'UnsupportedEnvironment'
  }

  It 'returns RealGdidPresent when a real PUID exists' {
    (Get-GdidVerdict $false $true $true $false) |
      Should Be 'RealGdidPresent'
  }

  It 'returns BlockDegraded when identifiers are absent but the gate is incomplete' {
    (Get-GdidVerdict $false $true $false $false) |
      Should Be 'BlockDegraded'
  }

  It 'returns ProtectedNoRealGdid only for the complete clean state' {
    (Get-GdidVerdict $false $true $false $true) |
      Should Be 'ProtectedNoRealGdid'
  }
}

Describe 'degdid firewall enforcement status' {
  It 'accepts an enforced rule with inactive noncurrent profiles' {
    (Test-FirewallEnforcementStatus 'ProfileInactive Enforced') |
      Should Be $true
  }

  It 'rejects disallowed or unresolved rules' {
    (Test-FirewallEnforcementStatus 'LocalFirewallRulesDisallowed') |
      Should Be $false
    (Test-FirewallEnforcementStatus 'ProfileInactive NoRemoteAddress') |
      Should Be $false
  }
}

Describe 'degdid wipe postcondition' {
  $model = [pscustomobject]@{
    Lids = @(
      [pscustomobject]@{ Name = 'TargetUserLid' },
      [pscustomobject]@{ Name = 'DefaultLid' },
      [pscustomobject]@{ Name = 'SystemLid' }
    )
  }

  It 'accepts a wipe only when active and residual real PUIDs are absent' {
    $inventory = [pscustomobject]@{
      Errors = @()
      AllRealPuids = @()
      ActiveRealPuids = @()
      ResidualRealPuids = @()
      Entries = @()
      PropertyValueNames = @()
      TokenKeys = @()
      CacheArtifacts = @()
    }
    $result = Test-WipePostcondition `
      -Inventory $inventory `
      -CapturedPuids @('0018000FC8CB93CC') `
      -Mode Wipe `
      -DecoyLid $null `
      -Model $model
    $result.Success | Should Be $true
  }

  It 'rejects a wipe when a captured old PUID remains in a cache' {
    $inventory = [pscustomobject]@{
      Errors = @()
      AllRealPuids = @('0018000FC8CB93CC')
      ActiveRealPuids = @()
      ResidualRealPuids = @('0018000FC8CB93CC')
      Entries = @()
      PropertyValueNames = @()
      TokenKeys = @()
      CacheArtifacts = @()
    }
    $result = Test-WipePostcondition `
      -Inventory $inventory `
      -CapturedPuids @('0018000FC8CB93CC') `
      -Mode Wipe `
      -DecoyLid $null `
      -Model $model
    $result.Success | Should Be $false
    ($result.Reasons -contains 'A captured old PUID remains.') |
      Should Be $true
  }

  It 'rejects a wipe when a different real-shaped PUID appears after settle' {
    $inventory = [pscustomobject]@{
      Errors = @()
      AllRealPuids = @('0018ABCDEF123456')
      ActiveRealPuids = @('0018ABCDEF123456')
      ResidualRealPuids = @()
      Entries = @()
      PropertyValueNames = @()
      TokenKeys = @()
      CacheArtifacts = @()
    }
    $result = Test-WipePostcondition `
      -Inventory $inventory `
      -CapturedPuids @('0018000FC8CB93CC') `
      -Mode Wipe `
      -DecoyLid $null `
      -Model $model
    $result.Success | Should Be $false
    ($result.Reasons -contains 'A real-shaped PUID exists in an active store.') |
      Should Be $true
  }

  It 'accepts a decoy only when every required LID store has that decoy' {
    $decoy = '0018ABCDEF123456'
    $entries = @(
      [pscustomobject]@{ Category='Active'; SourceKind='Lid'; Source='TargetUserLid'; RawIdentifier=$decoy; IsReal=$true },
      [pscustomobject]@{ Category='Active'; SourceKind='Lid'; Source='DefaultLid'; RawIdentifier=$decoy; IsReal=$true },
      [pscustomobject]@{ Category='Active'; SourceKind='Lid'; Source='SystemLid'; RawIdentifier=$decoy; IsReal=$true }
    )
    $inventory = [pscustomobject]@{
      Errors = @()
      AllRealPuids = @($decoy)
      ActiveRealPuids = @($decoy)
      ResidualRealPuids = @()
      Entries = $entries
      PropertyValueNames = @()
      TokenKeys = @()
      CacheArtifacts = @()
    }
    $result = Test-WipePostcondition `
      -Inventory $inventory `
      -CapturedPuids @('0018000FC8CB93CC') `
      -Mode Decoy `
      -DecoyLid $decoy `
      -Model $model
    $result.Success | Should Be $true
  }

  It 'rejects a wipe when non-real LID material remains' {
    $inventory = [pscustomobject]@{
      Errors = @()
      AllRealPuids = @()
      ActiveRealPuids = @()
      ResidualRealPuids = @()
      Entries = @(
        [pscustomobject]@{
          Category = 'Active'
          SourceKind = 'Lid'
          Source = 'TargetUserLid'
          RawIdentifier = 'unexpected-value'
          IsReal = $false
        }
      )
      PropertyValueNames = @()
      TokenKeys = @()
      CacheArtifacts = @()
    }
    $result = Test-WipePostcondition `
      -Inventory $inventory `
      -CapturedPuids @() `
      -Mode Wipe `
      -DecoyLid $null `
      -Model $model
    $result.Success | Should Be $false
    ($result.Reasons -contains 'An LID or Token DeviceId value remains.') |
      Should Be $true
  }

  It 'rejects a wipe when tickets or Property values remain' {
    $inventory = [pscustomobject]@{
      Errors = @()
      AllRealPuids = @()
      ActiveRealPuids = @()
      ResidualRealPuids = @()
      Entries = @()
      PropertyValueNames = @('other')
      TokenKeys = @([pscustomobject]@{ HasDeviceTicket = $true })
      CacheArtifacts = @([pscustomobject]@{ Present = $true })
    }
    $result = Test-WipePostcondition `
      -Inventory $inventory `
      -CapturedPuids @() `
      -Mode Wipe `
      -DecoyLid $null `
      -Model $model
    $result.Success | Should Be $false
    $result.Reasons.Count | Should Be 2
  }
}

Describe 'degdid mutation preflight' {
  It 'prioritizes an unresolved target over other support failures' {
    $environment = [pscustomobject]@{
      Target = $null
      TargetFailureReasons = @('No active target.')
      UnsupportedReasons = @('Managed.')
      IsAdministrator = $true
    }
    $result = Get-MutationPreflight -Environment $environment
    $result.Allowed | Should Be $false
    $result.ExitCode | Should Be 6
  }

  It 'refuses an unsupported environment before mutation' {
    $environment = [pscustomobject]@{
      Target = [pscustomobject]@{ Sid = 'S-1-5-21-test' }
      TargetFailureReasons = @()
      UnsupportedReasons = @('Multiple human profiles.')
      IsAdministrator = $true
    }
    $result = Get-MutationPreflight -Environment $environment
    $result.Allowed | Should Be $false
    $result.ExitCode | Should Be 2
  }
}

Describe 'degdid profile topology' {
  It 'allows one loaded target while reporting dormant profile artifacts' {
    $profiles = @(
      [pscustomobject]@{ Loaded = $false; SID = 'sandbox-a' },
      [pscustomobject]@{ Loaded = $false; SID = 'sandbox-b' },
      [pscustomobject]@{ Loaded = $true; SID = 'interactive' }
    )
    $topology = Get-ProfileTopology -Profiles $profiles
    $topology.ArtifactCount | Should Be 3
    $topology.LoadedCount | Should Be 1
    $topology.DormantCount | Should Be 2
    $topology.Loaded[0].SID | Should Be 'interactive'
  }

  It 'detects multiple simultaneously loaded profile hives' {
    $profiles = @(
      [pscustomobject]@{ Loaded = $true; SID = 'one' },
      [pscustomobject]@{ Loaded = $true; SID = 'two' }
    )
    (Get-ProfileTopology -Profiles $profiles).LoadedCount | Should Be 2
  }
}

Describe 'degdid fail-closed service sequencing' {
  BeforeEach {
    $script:testModel = [pscustomobject]@{
      Errors = @()
      Lids = @()
      CachePaths = @()
    }
    $script:emptyInventory = [pscustomobject]@{
      Errors = @()
      AllRealPuids = @()
      ActiveRealPuids = @()
      ResidualRealPuids = @()
      Entries = @()
      PropertyValueNames = @()
      TokenKeys = @()
      NegativeCacheKeys = @()
      CacheArtifacts = @()
    }
    $script:serviceSnapshot = [pscustomobject]@{
      Success = $true
      Error = $null
      Services = @(
        [pscustomobject]@{
          Name = 'wlidsvc'
          WasRunning = $true
          StartType = 'Manual'
        }
      )
    }

    Mock Get-GdidSourceModel { $script:testModel }
    Mock Test-GdidSourceModelSafety {
      [pscustomobject]@{ Success = $true; Errors = @() }
    }
    Mock Get-GdidInventory { $script:emptyInventory }
    Mock Get-GdidServiceSnapshot { $script:serviceSnapshot }
    Mock Stop-GdidServices { $true }
    Mock Resume-GdidServices { $true }
    Mock Set-FailClosedMintBarrier { $true }
  }

  It 'does not resume identity services when the pre-write gate fails' {
    Mock Get-ProtectionGate {
      [pscustomobject]@{ Healthy = $false }
    }

    $result = Invoke-IdentityMutation `
      -Mode Wipe `
      -Target ([pscustomobject]@{ Sid = 'test' })

    $result.Success | Should Be $false
    $result.ExitCode | Should Be 3
    $result.Message | Should Match 'services remain quiesced'
    Assert-MockCalled Resume-GdidServices 0 -Scope It
    Assert-MockCalled Set-FailClosedMintBarrier 1 -Scope It
  }

  It 're-quiesces all identity services when the gate is lost during settle' {
    $script:gateCall = 0
    Mock Get-ProtectionGate {
      $script:gateCall++
      [pscustomobject]@{ Healthy = $script:gateCall -lt 3 }
    }
    Mock Invoke-IdentityStoreChanges {}
    Mock Start-GdidSettleServices {
      [pscustomobject]@{ Success = $true; TemporaryNames = @() }
    }
    Mock Start-Sleep {}
    Mock Stop-GdidSettleServices { $true }
    Mock Test-GdidServiceRestoration { $true }

    $result = Invoke-IdentityMutation `
      -Mode Wipe `
      -Target ([pscustomobject]@{ Sid = 'test' })

    $result.Success | Should Be $false
    $result.ExitCode | Should Be 3
    $result.Message | Should Match 'services remain quiesced'
    Assert-MockCalled Set-FailClosedMintBarrier 1 -Scope It
    Assert-MockCalled Test-GdidServiceRestoration 0 -Scope It
  }
}

Describe 'degdid operation ledger scoping' {
  It 'does not shadow variables used by an operation action' {
    $results = New-Object System.Collections.Generic.List[object]
    $name = 'wlidsvc'
    $script:observedServiceName = $null
    $ok = Add-OperationResult `
      -Results $results `
      -OperationName 'StopService:wlidsvc' `
      -Action { $script:observedServiceName = $name }
    $ok | Should Be $true
    $script:observedServiceName | Should Be 'wlidsvc'
    $results[0].Name | Should Be 'StopService:wlidsvc'
  }
}

Describe 'degdid Unblock sequencing' {
  It 'preflights hosts, removes firewall first, then removes hosts and flushes DNS' {
    $script:unblockOrder = New-Object System.Collections.Generic.List[string]
    Mock Invoke-HostsDocumentChange {
      param($Mode, $DryRun)
      if ($DryRun) {
        [void]$script:unblockOrder.Add('hosts-preflight')
      } else {
        [void]$script:unblockOrder.Add('hosts-remove')
      }
      [pscustomobject]@{ Mode = $Mode; DryRun = [bool]$DryRun }
    }
    Mock Remove-FirewallBlock {
      [void]$script:unblockOrder.Add('firewall-remove')
      [pscustomobject]@{ Success = $true; Message = 'removed' }
    }
    Mock Invoke-DnsFlush {
      [void]$script:unblockOrder.Add('dns-flush')
    }
    Mock Read-HostsDocument {
      [pscustomobject]@{
        State = [pscustomobject]@{ State = 'Absent' }
      }
    }

    $result = Invoke-UnblockConfiguration
    $result.Success | Should Be $true
    ($script:unblockOrder -join ',') |
      Should Be 'hosts-preflight,firewall-remove,hosts-remove,dns-flush'
  }

  It 'leaves hosts untouched when firewall cleanup fails' {
    Mock Invoke-HostsDocumentChange {
      [pscustomobject]@{ Mode = 'Unblock'; DryRun = $true }
    }
    Mock Remove-FirewallBlock {
      [pscustomobject]@{ Success = $false; Message = 'failed' }
    }
    Mock Invoke-DnsFlush {}

    $result = Invoke-UnblockConfiguration
    $result.Success | Should Be $false
    $result.ExitCode | Should Be 3
    Assert-MockCalled Invoke-HostsDocumentChange 1 -Scope It
    Assert-MockCalled Invoke-DnsFlush 0 -Scope It
  }
}
