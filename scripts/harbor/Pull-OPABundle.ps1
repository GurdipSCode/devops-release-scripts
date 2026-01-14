<#
.SYNOPSIS
  Pull an OPA bundle from Harbor (OCI registry) and evaluate a decision.

.PREREQS
  - oras (https://oras.land/) in PATH
  - opa  (Open Policy Agent CLI) in PATH
  - Harbor repo contains an OCI artifact that is an OPA bundle (tar.gz) or an image containing the bundle layers.

.EXAMPLE
  .\Invoke-OpaBundleFromHarbor.ps1 `
    -Ref "harbor.company.internal/policy/tenant-guardrails:1.2.3" `
    -Decision "data.authz.allow" `
    -InputJsonPath ".\input.json"

.EXAMPLE (with login)
  .\Invoke-OpaBundleFromHarbor.ps1 `
    -Ref "harbor.company.internal/policy/tenant-guardrails:1.2.3" `
    -Decision "data.authz.allow" `
    -Username "robot$ci" `
    -Password $env:HARBOR_TOKEN `
    -InputJsonPath ".\input.json"
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [string]$Ref,   # e.g. harbor.example.com/project/bundle:tag

  [Parameter(Mandatory=$true)]
  [string]$Decision,  # e.g. data.authz.allow

  [Parameter(Mandatory=$false)]
  [string]$InputJsonPath,

  [Parameter(Mandatory=$false)]
  [string]$OutputFormat = "pretty", # pretty | json | raw

  [Parameter(Mandatory=$false)]
  [string]$Username,

  [Parameter(Mandatory=$false)]
  [string]$Password,

  [Parameter(Mandatory=$false)]
  [switch]$InsecureTls, # oras --insecure / allow self-signed

  [Parameter(Mandatory=$false)]
  [switch]$PlainHttp,   # oras --plain-http (ONLY if your registry is http://)

  [Parameter(Mandatory=$false)]
  [string]$WorkDir = (Join-Path $env:TEMP ("opa-bundle-" + [Guid]::NewGuid().ToString("n")))
)

$ErrorActionPreference = "Stop"

function Assert-Cmd([string]$Name) {
  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    throw "Required command '$Name' not found in PATH."
  }
}

Assert-Cmd "oras"
Assert-Cmd "opa"

New-Item -ItemType Directory -Path $WorkDir | Out-Null

try {
  # Optionally login (oras can also use existing docker credential store; this just makes it explicit)
  if ($Username -and $Password) {
    $registry = ($Ref -split "/")[0]
    Write-Host "Logging into registry: $registry"
    $loginArgs = @("login", $registry, "-u", $Username, "-p", $Password)
    if ($InsecureTls) { $loginArgs += "--insecure" }
    if ($PlainHttp)   { $loginArgs += "--plain-http" }
    & oras @loginArgs | Out-Null
  }

  Write-Host "Pulling OPA bundle from: $Ref"
  Push-Location $WorkDir

  $pullArgs = @("pull", $Ref)
  if ($InsecureTls) { $pullArgs += "--insecure" }
  if ($PlainHttp)   { $pullArgs += "--plain-http" }

  & oras @pullArgs | Out-Null

  # Find a bundle archive.
  # Common outputs are *.tar.gz or *.tgz (depending on how it was pushed).
  $bundle = Get-ChildItem -File -Recurse -Include *.tar.gz,*.tgz | Select-Object -First 1
  if (-not $bundle) {
    throw "No *.tar.gz or *.tgz found after pulling '$Ref'. Check how the artifact is packaged in Harbor."
  }

  Write-Host "Using bundle: $($bundle.FullName)"

  # Build opa eval args
  $opaArgs = @(
    "eval",
    "--bundle", $bundle.FullName,
    "--format", $OutputFormat,
    $Decision
  )

  if ($InputJsonPath) {
    if (-not (Test-Path $InputJsonPath)) { throw "InputJsonPath not found: $InputJsonPath" }
    $opaArgs += @("--input", (Resolve-Path $InputJsonPath).Path)
  }

  Write-Host "Evaluating decision: $Decision"
  & opa @opaArgs
}
finally {
  Pop-Location -ErrorAction SilentlyContinue
  # Clean up workdir (comment out if you want to inspect pulled files)
  Remove-Item -Recurse -Force $WorkDir -ErrorAction SilentlyContinue
}
