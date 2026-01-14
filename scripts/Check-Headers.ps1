# Octopus Deploy - Security Headers Check with Environment-Aware URL Selection
param(
    [string]$Url = $(
            $OctopusParameters["Netlify.SiteURL"]
        }
    ),
    [string]$MinimumScore = $OctopusParameters["SecurityCheck.MinimumScore"] ?? "70",
    [bool]$FailOnLowScore = [System.Convert]::ToBoolean($OctopusParameters["SecurityCheck.FailOnLowScore"] ?? "true"),
    [bool]$DetailedOutput = [System.Convert]::ToBoolean($OctopusParameters["SecurityCheck.DetailedOutput"] ?? "true")
)

function Get-SecurityHeaderRecommendation {
    param([string]$HeaderName)

    $recommendations = @{
        "Strict-Transport-Security"      = "max-age=31536000; includeSubDomains; preload"
        "Content-Security-Policy"        = "default-src 'self'; script-src 'self'; style-src 'self'"
        "X-Content-Type-Options"         = "nosniff"
        "X-Frame-Options"                = "DENY or SAMEORIGIN"
        "Referrer-Policy"                = "strict-origin-when-cross-origin"
        "Permissions-Policy"             = "geolocation=(), microphone=(), camera=()"
        "X-XSS-Protection"               = "1; mode=block"
        "Cross-Origin-Embedder-Policy"   = "require-corp"
        "Cross-Origin-Opener-Policy"     = "same-origin"
        "Cross-Origin-Resource-Policy"   = "same-origin"
    }

    return $recommendations[$HeaderName]
}

function Invoke-SecurityHeadersCheck {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Url,

        [Parameter(Mandatory=$false)]
        [int]$MinimumScore = 70,

        [Parameter(Mandatory=$false)]
        [bool]$FailOnLowScore = $true,

        [Parameter(Mandatory=$false)]
        [bool]$DetailedOutput = $true,

        [Parameter(Mandatory=$false)]
        [hashtable]$OctopusParameters = $null
    )

    # Resolve URL fallback(s)
    if ([string]::IsNullOrWhiteSpace($Url)) {
        if ($OctopusParameters -and $OctopusParameters.ContainsKey("Netlify.SiteUrl")) {
            Write-Host "⚠ No URL from deployment step, checking Netlify.SiteUrl..." -ForegroundColor Yellow
            $Url = $OctopusParameters["Netlify.SiteUrl"]
        } elseif ($OctopusParameters -and $OctopusParameters.ContainsKey("Netlify.SiteURL")) {
            Write-Host "⚠ No URL from deployment step, checking Netlify.SiteURL..." -ForegroundColor Yellow
            $Url = $OctopusParameters["Netlify.SiteURL"]
        }
    }

    if ([string]::IsNullOrWhiteSpace($Url)) {
        Write-Host ""
        Write-Host "❌ ERROR: No URL available for security check" -ForegroundColor Red
        if ($OctopusParameters) {
            Write-Host "Environment: $($OctopusParameters['Octopus.Environment.Name'])" -ForegroundColor Gray
        }
        Write-Host "Please ensure the deployment step has run successfully." -ForegroundColor Gray
        Write-Host ""
        return [pscustomobject]@{
            Success        = $false
            Score          = 0
            MinimumScore   = $MinimumScore
            FailOnLowScore = $FailOnLowScore
            Url            = $Url
            Results        = @()
            MissingCritical= @()
            Error          = "No URL available"
        }
    }

    Write-Host "##octopus[stdout-highlight]"
    Write-Host "🔒 Security Header Analysis" -ForegroundColor Cyan
    Write-Host "Target URL: $Url" -ForegroundColor White
    if ($OctopusParameters) {
        Write-Host "Environment: $($OctopusParameters['Octopus.Environment.Name'])" -ForegroundColor White
    }
    Write-Host "Minimum Score Required: $MinimumScore%" -ForegroundColor White
    Write-Host "=" * 70
    Write-Host ""

    try {
        # Make request
        Write-Host "Making request to $Url..." -ForegroundColor Gray
        $response = Invoke-WebRequest -Uri $Url -Method Head -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
        Write-Host "✓ Response received (Status: $($response.StatusCode))" -ForegroundColor Green
        Write-Host ""

        # Define security headers
        $securityHeaders = @{
            "Strict-Transport-Security" = @{
                Description = "Enforces HTTPS connections"
                Severity    = "High"
                Critical    = $true
            }
            "Content-Security-Policy" = @{
                Description = "Prevents XSS and injection attacks"
                Severity    = "High"
                Critical    = $true
            }
            "X-Content-Type-Options" = @{
                Description = "Prevents MIME-sniffing"
                Severity    = "Medium"
                Critical    = $false
            }
            "X-Frame-Options" = @{
                Description = "Prevents clickjacking"
                Severity    = "Medium"
                Critical    = $false
            }
            "Referrer-Policy" = @{
                Description = "Controls referrer information"
                Severity    = "Low"
                Critical    = $false
            }
            "Permissions-Policy" = @{
                Description = "Controls browser features"
                Severity    = "Low"
                Critical    = $false
            }
            "X-XSS-Protection" = @{
                Description = "Enables XSS filter (legacy)"
                Severity    = "Low"
                Critical    = $false
            }
            "Cross-Origin-Embedder-Policy" = @{
                Description = "Controls embedding of cross-origin resources"
                Severity    = "Low"
                Critical    = $false
            }
            "Cross-Origin-Opener-Policy" = @{
                Description = "Isolates browsing context"
                Severity    = "Low"
                Critical    = $false
            }
            "Cross-Origin-Resource-Policy" = @{
                Description = "Controls resource loading"
                Severity    = "Low"
                Critical    = $false
            }
        }

        $results = @()
        $criticalMissing = New-Object System.Collections.Generic.List[string]

        # Sort High -> Medium -> Low
        $sortedHeaders = $securityHeaders.GetEnumerator() | Sort-Object {
            switch($_.Value.Severity) {
                "High"   { 0 }
                "Medium" { 1 }
                "Low"    { 2 }
                default  { 3 }
            }
        }

        foreach ($header in $sortedHeaders) {
            $headerName  = $header.Key
            $headerInfo  = $header.Value
            $headerValue = $response.Headers[$headerName]

            $present = -not [string]::IsNullOrWhiteSpace($headerValue)
            if (-not $present -and $headerInfo.Critical) {
                $criticalMissing.Add($headerName) | Out-Null
            }

            $recommendation = Get-SecurityHeaderRecommendation -HeaderName $headerName

            # Output line(s)
            if ($present) {
                $statusIcon = "✅"
                $statusText = "Present"
                $color = "Green"
            } else {
                $statusIcon = if ($headerInfo.Critical) { "❌" } else { "⚠️" }
                $statusText = "Missing"
                $color = if ($headerInfo.Critical) { "Red" } else { "Yellow" }
            }

            Write-Host "$statusIcon $headerName [$($headerInfo.Severity)] - $($headerInfo.Description)" -ForegroundColor $color
            if ($DetailedOutput) {
                if ($present) {
                    Write-Host "    Value: $headerValue" -ForegroundColor Gray
                } else {
                    Write-Host "    Recommended: $recommendation" -ForegroundColor Gray
                }
            }

            $results += [pscustomobject]@{
                Header         = $headerName
                Present        = $present
                Severity       = $headerInfo.Severity
                Critical       = [bool]$headerInfo.Critical
                Description    = $headerInfo.Description
                Value          = $headerValue
                Recommendation = $recommendation
            }
        }

        # Score calculation
        # Weighted: High=15, Medium=10, Low=5 (missing deducts)
        $weights = @{ High = 15; Medium = 10; Low = 5 }
        $maxPoints = 0
        $earnedPoints = 0

        foreach ($r in $results) {
            $w = $weights[$r.Severity]
            $maxPoints += $w
            if ($r.Present) { $earnedPoints += $w }
        }

        $score = if ($maxPoints -gt 0) { [math]::Round(($earnedPoints / $maxPoints) * 100, 0) } else { 0 }

        Write-Host ""
        Write-Host ("=" * 70)
        Write-Host "📊 Score: $score% (Minimum required: $MinimumScore%)" -ForegroundColor Cyan

        if ($criticalMissing.Count -gt 0) {
            Write-Host "❌ Missing CRITICAL headers: $($criticalMissing -join ', ')" -ForegroundColor Red
        }

        $success = $true
        if ($score -lt $MinimumScore) {
            Write-Host "⚠ Score is below minimum threshold." -ForegroundColor Yellow
            if ($FailOnLowScore) {
                Write-Host "❌ FailOnLowScore is enabled: failing step." -ForegroundColor Red
                $success = $false
            }
        } else {
            Write-Host "✅ Meets minimum score threshold." -ForegroundColor Green
        }

        return [pscustomobject]@{
            Success         = $success
            Score           = $score
            MinimumScore    = $MinimumScore
            FailOnLowScore  = $FailOnLowScore
            Url             = $Url
            Results         = $results
            MissingCritical = $criticalMissing.ToArray()
            StatusCode      = $response.StatusCode
        }

    } catch {
        Write-Host ""
        Write-Host "❌ ERROR: Failed to fetch headers from $Url" -ForegroundColor Red
        Write-Host "Details: $_" -ForegroundColor Gray
        Write-Host ""

        return [pscustomobject]@{
            Success        = $false
            Score          = 0
            MinimumScore   = $MinimumScore
            FailOnLowScore = $FailOnLowScore
            Url            = $Url
            Results        = @()
            MissingCritical= @()
            Error          = $_.Exception.Message
        }
    }
}

# ----------------------------
# Execute (and preserve behavior)
# ----------------------------
# Normalize MinimumScore to int (param is string in Octopus variables often)
[int]$minScoreInt = 70
if (-not [int]::TryParse($MinimumScore, [ref]$minScoreInt)) { $minScoreInt = 70 }

$result = Invoke-SecurityHeadersCheck `
    -Url $Url `
    -MinimumScore $minScoreInt `
    -FailOnLowScore $FailOnLowScore `
    -DetailedOutput $DetailedOutput `
    -OctopusParameters $OctopusParameters

if (-not $result.Success) {
    exit 1
}

exit 0
