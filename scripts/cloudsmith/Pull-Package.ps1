function Pull-Package {
    <#
    .SYNOPSIS
      Downloads a Portfolio .tgz from Cloudsmith using the Octopus release number, extracts it to a target folder,
      and cleans up the archive files.

    .PARAMETER FolderPath
      Destination folder to (re)create and extract into.

    .PARAMETER ReleaseNumber
      Release number to use in the artifact name/URL. Defaults to Octopus.Release.Number.

    .PARAMETER BaseUrl
      Cloudsmith base URL (everything up to /Portfolio-<release>.tgz).

    .PARAMETER KeepArchives
      If set, keeps the downloaded .tgz and intermediate .tar instead of deleting.

    .EXAMPLE
      Invoke-PortfolioDeployExtract

    .EXAMPLE
      Invoke-PortfolioDeployExtract -FolderPath 'C:\deployment\portfolio' -ReleaseNumber '1.2.345'
    #>

    [CmdletBinding()]
    param(
        [string]$FolderPath = 'C:\deployment\portfolio',
        [string]$ReleaseNumber = $OctopusParameters["Octopus.Release.Number"],
        [string]$BaseUrl = 'https://dl.cloudsmith.io/public/gurdipdevops/portfolio/raw/files',
        [switch]$KeepArchives
    )

    $ErrorActionPreference = "Stop"

    if (-not $ReleaseNumber) {
        throw "ReleaseNumber is required (Octopus.Release.Number was empty)."
    }

    # Ensure the folder exists and is empty
    if (Test-Path $FolderPath) {
        Write-Host "Cleaning existing folder: $FolderPath"
        Remove-Item -Path $FolderPath -Recurse -Force | Out-Null
    }

    Write-Host "Creating deployment folder: $FolderPath"
    New-Item -ItemType Directory -Path $FolderPath | Out-Null

    # Build file paths
