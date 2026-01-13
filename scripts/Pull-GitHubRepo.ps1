param (
    [string]$RepoUrl,
    [string]$Branch = "main",
    [string]$Destination = "repo"
)

if (Test-Path "$Destination\.git") {
    Write-Host "Repo exists, fetching updates..."
    git -C $Destination fetch origin
    git -C $Destination checkout $Branch
    git -C $Destination pull origin $Branch
} else {
    git clone --branch $Branch $RepoUrl $Destination
}
