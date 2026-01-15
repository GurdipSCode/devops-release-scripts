function Invoke-VaultAppRoleFetchSecretsToOctopusOutputs {
<#
.SYNOPSIS
  Logs into HashiCorp Vault using AppRole, retrieves secrets from multiple KV v2 paths,
  and sets each key as an Octopus output variable (sensitive).

.DESCRIPTION
  - Authenticates to Vault via /v1/auth/approle/login
  - Fetches each secret path under /v1/<path>
  - Collects all keys under .data.data (KV v2)
  - Sets each key as an Octopus output variable using Set-OctopusVariable -Sensitive

.PARAMETER VaultAddress
  Vault base URL (e.g. http://vault.gssira.com:8200)

.PARAMETER Namespace
  Vault namespace (X-Vault-Namespace header), if your Vault uses namespaces.

.PARAMETER RoleID
  AppRole role_id (defaults from OctopusParameters["Vault.RoleId"]).

.PARAMETER SecretID
  AppRole secret_id (defaults from OctopusParameters["Vault.SecretId"]).

.PARAMETER SecretPaths
  Array of Vault secret paths to fetch (KV v2 paths like kvv2/data/FOO).

.PARAMETER FailOnMissingAnyPath
  If set, throws when any secret path cannot be retrieved (default: false).
  Otherwise it continues and only fails if none are retrieved.

.OUTPUTS
  Returns a hashtable of all retrieved key/value pairs.
#>

  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $false)]
    [string]$VaultAddress = "http://vault.gssira.com:8200",

    [Parameter(Mandatory = $false)]
    [string]$Namespace = "DevOps/Portfolio",

    [Parameter(Mandatory = $false)]
    [string]$RoleID = $OctopusParameters["Vault.RoleId"],

    [Parameter(Mandatory = $false)]
    [string]$SecretID = $OctopusParameters["Vault.SecretId"],

    [Parameter(Mandatory = $false)]
    [string[]]$SecretPaths = @(
      "kvv2/data/NETLIFY_AUTH_TOKEN_v2",
      "kvv2/data/PAGEVITALS_API_KEY"
    ),

    [Parameter(Mandatory = $false)]
    [switch]$FailOnMissingAnyPath
  )

  $ErrorActionPreference = "Stop"

  if ([string]::IsNullOrWhiteSpace($VaultAddress)) { throw "VaultAddress is required." }
  if ([string]::IsNullOrWhiteSpace($RoleID)) { throw "RoleID is required (Vault.RoleId)." }
  if ([string]::IsNullOrWhiteSpace($SecretID)) { throw "SecretID is required (Vault.SecretId)." }
  if (-not $SecretPaths -or $SecretPaths.Count -eq 0) { throw "SecretPaths must contain at least one path." }

  # -----------------------------
  # Step 1: Login using AppRole
  # -----------------------------
