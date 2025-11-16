# Add URL to PageVitals for Performance Monitoring
param(
    [Parameter(Mandatory=$true)]
    [string]$Url,
    
    [Parameter(Mandatory=$true)]
    [string]$ApiKey,
    
    [string]$Name = $null,
    [string]$Interval = "3600",  # Check every hour (in seconds)
    [string[]]$Locations = @("us-east"),  # Default location
    [string]$Device = "desktop",  # desktop or mobile
    [bool]$Lighthouse = $true,
    [bool]$PerformanceMetrics = $true
)

Write-Host "=" * 70
Write-Host "📊 Adding URL to PageVitals" -ForegroundColor Cyan
Write-Host "=" * 70
Write-Host ""

try {
    # Validate URL
    if (-not [System.Uri]::IsWellFormedUriString($Url, [System.UriKind]::Absolute)) {
        throw "Invalid URL format: $Url"
    }
    
    # Generate a name if not provided
    if ([string]::IsNullOrWhiteSpace($Name)) {
        $uri = [System.Uri]$Url
        $Name = $uri.Host
    }
    
    Write-Host "Configuration:" -ForegroundColor Yellow
    Write-Host "  URL: $Url" -ForegroundColor Gray
    Write-Host "  Name: $Name" -ForegroundColor Gray
    Write-Host "  Interval: $Interval seconds" -ForegroundColor Gray
    Write-Host "  Locations: $($Locations -join ', ')" -ForegroundColor Gray
    Write-Host "  Device: $Device" -ForegroundColor Gray
    Write-Host "  Lighthouse: $Lighthouse" -ForegroundColor Gray
    Write-Host ""
    
    # Prepare the request body
    $body = @{
        url = $Url
        name = $Name
        interval = [int]$Interval
        locations = $Locations
        device = $Device
        lighthouse = $Lighthouse
        performanceMetrics = $PerformanceMetrics
    } | ConvertTo-Json
    
    # API endpoint
    $apiEndpoint = "https://api.pagevitals.com/v1/monitors"
    
    # Headers
    $headers = @{
        "Authorization" = "Bearer $ApiKey"
        "Content-Type" = "application/json"
        "Accept" = "application/json"
    }
    
    Write-Host "Sending request to PageVitals API..." -ForegroundColor White
    
    # Make the API request
    $response = Invoke-RestMethod -Uri $apiEndpoint -Method Post -Headers $headers -Body $body -ErrorAction Stop
    
    Write-Host ""
    Write-Host "✅ URL added successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Monitor Details:" -ForegroundColor Cyan
    Write-Host "  Monitor ID: $($response.id)" -ForegroundColor Gray
    Write-Host "  Name: $($response.name)" -ForegroundColor Gray
    Write-Host "  URL: $($response.url)" -ForegroundColor Gray
    Write-Host "  Status: $($response.status)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "🔗 View in PageVitals: https://app.pagevitals.com/monitors/$($response.id)" -ForegroundColor Cyan
    Write-Host ""
    
    # Return the monitor ID for use in other scripts
    return $response.id
    
} catch {
    Write-Host ""
    Write-Host "❌ Failed to add URL to PageVitals" -ForegroundColor Red
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    
    if ($_.ErrorDetails.Message) {
        $errorDetails = $_.ErrorDetails.Message | ConvertFrom-Json
        Write-Host "Details: $($errorDetails.message)" -ForegroundColor Red
    }
    
    Write-Host ""
    exit 1
}
