function Invoke-NetlifyDeployFromOctopus {
    <#
    .SYNOPSIS
      Deploys a built site directory to Netlify, using Octopus variables when available,
      with fallbacks for local testing.

    .PARAMETER BuildDirectory
      Directory containing the built static site (default: c:\deployment\portfolio\package)

    .PARAMETER ProductionAlias
      Alias to use for non-production deploys (default: gurdipdevportfolio)

    .PARAMETER TokensStepName
      Octopus step name that outputs netlify/pagevitals tokens (default: Get Tokens)

    .PARAMETER NetlifyExe
      Netlify CLI command to run. Default uses npx to avoid global installs.

    .NOTES
      Expects Octopus variables:
        Netlify.SiteID
        Netlify.SiteUrl
      Expects step outputs:
        Octopus.Action[Get Tokens].Output.netlify_auth_token
        Octopus.Action[Get Tokens].Output.pagevitals_api_key
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$BuildDirectory = "c:\deployment\portfolio\package",

        [Parameter(Mandatory = $false)]
        [string]$ProductionAlias = "gurdipdevportfolio",

        [Parameter(Mandatory = $false)]
        [string]$TokensStepName = "Get Tokens",

        [Parameter(Mandatory = $false)]
        [ValidateSet("npx","netlify")]
        [string]$NetlifyExe = "npx"
    )

    $ErrorActionPreference = "Stop"

    function Get-OctopusOutputVar([string]$stepName, [string]$varName) {
        $key = "Octopus.Action[$stepName].Output.$varName"
        return $OctopusParameters[$ke]()
