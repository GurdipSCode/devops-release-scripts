function Invoke-OpaDnsControlBundleCheck {
<#
.SYNOPSIS
  Pull an OPA bundle (OCI artifact) from Harbor and run bundle tests + DNSControl evaluation in Octopus.

.ASSUMES
  A previous Octopus step (e.g. "Get Harbor Creds") exported output variables:
    - HarborUsername
    - HarborPassword
  Accessed as:
    $OctopusParameters["Octopus.Action[Get Harbor Creds].Output.HarborUsername"]
    $OctopusParameters["Octopus.Action[Get Harbor Creds].Output.HarborPassword"]

.PREREQS
  - oras.exe in PATH
  - opa.exe  in PATH
#>

  [CmdletBinding()]
  param(
    # Required
    [string]$BundleRef      = $OctopusParameters["Opa.BundleRef"],
    [string]$InputJsonPath  = $OctopusParameters["Opa.InputJsonPath"],

    # Optional (sane defaults)
    [string]$DecisionQuery  = ($OctopusParameters["Opa.DecisionQuery"] ?? "data.dnscontrol.deny"),
    [bool]  $FailOnDeny     = [System.Convert]::ToBoolean($OctopusParameters["Opa.FailOnDeny"] ?? "true"),

    # Harbor cred source
    [string]$CredsStepName  = ($OctopusParameters["Harbor.CredsStepName"] ?? "Get Harbor Creds"),

    # Allow overrides (if set, these win)
    [string]$HarborUsername = $OctopusParameters["Harbor.Username"],
    [string]$HarborPassword = $OctopusParameters["Harbor.Password"],

    [bool]  $InsecureTls    = [System.Convert]::ToBoolean($OctopusParameters["Harbor.InsecureTls"] ?? "false"),
    [bool]  $PlainHttp      = [System.Convert]::ToBoolean($OctopusParameters["Harbor.PlainHttp"] ?? "false")
  )

  $ErrorActionPreference = "Stop"

  function Assert-Cmd([string]$name) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
      throw "Required command '$name' not found in PATH. Ensure it is installed on the Octopus worker, or bundled with the step."
    }
  }

  function Invoke-External([string]$exe, [string[]]$args) {
    $argLine = ($args | ForEach-Object { if ($_ -match '\s') { "`"$_`"" } else { $_ } }) -join " "
    Write-Host ">> $exe $argLine"

    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $exe
    $pinfo.Arguments = $argLine
    $pinfo.RedirectStandardOutput = $true
    $pinfo.RedirectStandardError = $true
    $pinfo.UseShellExecute = $false
    $pinfo.CreateNoWindow = $true

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    [void]$p.Start()
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()

    if ($stdout) { Write-Host $stdout.TrimEnd() }
    if ($p.ExitCode -ne 0) {
      if ($stderr) { Write-Error $stderr.TrimEnd() }
      throw "Command failed (exit $($p.ExitCode)): $exe $argLine"
    }

    return $stdout
  }

  function Get-OctopusOutputVar([string]$stepName, [string]$varName) {
    $key = "Octopus.Action[$stepName].Output.$varName"
    return $OctopusParameters[$key]
  }

  if (-not $BundleRef)     { throw "Opa.BundleRef is required (e.g., harbor.company.internal/policy/dnscontrol:1.2.3)" }
  if (-not $InputJsonPath) { throw "Opa.InputJsonPath is required (path to DNSControl JSON input on the worker)" }
  if (-not (Test-Path $InputJsonPath)) { throw "Input JSON file not found: $InputJsonPath" }

  Assert-Cmd "oras"
  Assert-Cmd "opa"

  # Pull Harbor creds from previous step outputs if not explicitly set
  if (-not $HarborUsername) { $HarborUsername = Get-OctopusOutputVar -stepName $CredsStepName -varName "HarborUsername" }
  if (-not $HarborPassword) { $HarborPassword = Get-OctopusOutputVar -stepName $CredsStepName -varName "HarborPassword" }

  if (-not $HarborUsername -or -not $HarborPassword) {
    throw "Harbor credentials not found. Either set Harbor.Username/Harbor.Password, or ensure the step '$CredsStepName' outputs HarborUsername and HarborPassword."
  }

  $workDir = Join-Path $env:TEMP ("opa-dnscontrol-" + [Guid]::NewGuid().ToString("n"))
  New-Item -ItemType Directory -Force -Path $workDir | Out-Null

  try {
    $registry = ($BundleRef -split "/")[0]
    Write-Host "Logging into Harbor registry: $registry (via creds from step '$CredsStepName')"

    $loginArgs = @("login", $registry, "-u", $HarborUsername, "-p", $HarborPassword)
    if ($InsecureTls) { $loginArgs += "--insecure" }
    if ($PlainHttp)   { $loginArgs += "--plain-http" }
    Invoke-External "oras" $loginArgs | Out-Null

    Write-Host "Pulling OPA bundle artifact from Harbor: $BundleRef"
    $pullArgs = @("pull", "-o", $workDir, $BundleRef)
    if ($InsecureTls) { $pullArgs += "--insecure" }
    if ($PlainHttp)   { $pullArgs += "--plain-http" }
    Invoke-External "oras" $pullArgs | Out-Null

    $bundle = Get-ChildItem -Path $workDir -Recurse -File -Include *.tar.gz,*.tgz | Select-Object -First 1
    if (-not $bundle) {
      $files = (Get-ChildItem -Path $workDir -Recurse -File | Select-Object -ExpandProperty FullName)
      throw "No bundle archive (*.tar.gz / *.tgz) found after oras pull. Files pulled:`n$($files -join "`n")"
    }

    Write-Host "Bundle archive found: $($bundle.FullName)"

    Write-Host "Running OPA unit tests from bundle..."
    Invoke-External "opa" @("test", "--bundle", $bundle.FullName) | Out-Null
    Write-Host "OPA tests: PASSED"

    Write-Host "Evaluating decision query: $DecisionQuery"
    $evalJson = Invoke-External "opa" @(
      "eval",
      "--bundle", $bundle.FullName,
      "--format", "json",
      "--input", (Resolve-Path $InputJsonPath).Path,
      $DecisionQuery
    )

    $parsed = $evalJson | ConvertFrom-Json

    $value = $null
    if ($parsed.result -and $parsed.result.Count -gt 0 -and
        $parsed.result[0].expressions -and $parsed.result[0].expressions.Count -gt 0) {
      $value = $parsed.result[0].expressions[0].value
    }

    # Deny detection tuned for "data.*.deny" patterns:
    # true => deny
    # non-empty array/object/string => deny
    $denied = $false
    if ($value -eq $true) { $denied = $true }
    elseif ($null -ne $value) {
      if ($value -is [string]) {
        if ($value.Trim().Length -gt 0) { $denied = $true }
      } elseif ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
        $hasAny = $false
        foreach ($x in $value) { $hasAny = $true; break }
        if ($hasAny) { $denied = $true }
      } else {
        $denied = $true
      }
    }

    if ($denied) {
      Write-Host "OPA decision indicates DENY. Decision value:"
      ($value | ConvertTo-Json -Depth 20) | Write-Host

      if ($FailOnDeny) {
        throw "DNSControl policy check failed (denied by OPA decision: $DecisionQuery)."
      } else {
        Write-Warning "Denied by policy, but Opa.FailOnDeny=false so continuing."
      }
    } else {
      Write-Host "OPA decision indicates ALLOW (no deny result)."
    }

    # Return details for callers
    return [pscustomobject]@{
      BundleRef     = $BundleRef
      BundlePath    = $bundle.FullName
      DecisionQuery = $DecisionQuery
      Denied        = $denied
      WorkDir       = $workDir
    }
  }
  finally {
    Remove-Item -Recurse -Force $workDir -ErrorAction SilentlyContinue
  }
}
