# ============================================
# COMPREHENSIVE SSL/TLS Security Check Script for Octopus Deploy
# + SARIF v2.1.0 Output
# ============================================

param(
    [Parameter(Mandatory=$false)]
    [string]$Url = $OctopusParameters["Netlify.SiteURL"],

    [Parameter(Mandatory=$false)]
    [int]$MinCertValidityDays = 30,

    [Parameter(Mandatory=$false)]
    [int]$MinKeySize = 2048,

    [Parameter(Mandatory=$false)]
    [bool]$CheckOCSP = $true,

    [Parameter(Mandatory=$false)]
    [bool]$StrictMode = $false,  # If true, warnings become failures

    # SARIF output
    [Parameter(Mandatory=$false)]
    [bool]$WriteSarif = $true,

    [Parameter(Mandatory=$false)]
    [string]$SarifPath = $(
        if ($OctopusParameters.ContainsKey("Octopus.Action.Package.CustomInstallationDirectory")) {
            Join-Path $OctopusParameters["Octopus.Action.Package.CustomInstallationDirectory"] "ssl-tls-security.sarif"
        } elseif ($env:OctopusWorkingDirectory) {
            Join-Path $env:OctopusWorkingDirectory "ssl-tls-security.sarif"
        } else {
            Join-Path (Get-Location) "ssl-tls-security.sarif"
        }
    )
)

# ----------------------------
# Guardrails / normalization
# ----------------------------
if ([string]::IsNullOrWhiteSpace($Url)) {
    Write-Error "Netlify.SiteURL is not set (and -Url was not provided)."
    exit 1
}

# Extract hostname from URL if full URL provided
if ($Url -match '^https?://([^/]+)') {
    $hostname = $matches[1]
} else {
    $hostname = $Url
}

Write-Host "🔒 Starting COMPREHENSIVE SSL/TLS Security Check for: $hostname"
Write-Host "=" * 80

$allChecksPassed = $true

$findings = @{
    Critical = @()
    High     = @()
    Medium   = @()
    Low      = @()
    Info     = @()
}

# For SARIF: capture results with rule ids and optional check name
$sarifResults = New-Object System.Collections.Generic.List[object]

function Get-SarifLevelFromSeverity {
    param([string]$Severity)
    switch ($Severity) {
        "Critical" { return "error" }
        "High"     { return "error" }
        "Medium"   { return "warning" }
        "Low"      { return "note" }
        "Info"     { return "note" }
        default    { return "note" }
    }
}

function Add-Finding {
    param(
        [Parameter(Mandatory=$true)][string]$Severity,
        [Parameter(Mandatory=$true)][string]$Message,
        [Parameter(Mandatory=$false)][string]$RuleId = "SSL0000",
        [Parameter(Mandatory=$false)][string]$Check = ""
    )

    $findings[$Severity] += $Message

    $fg = switch ($Severity) {
        "Critical" { "Red" }
        "High"     { "Red" }
        "Medium"   { "Yellow" }
        "Low"      { "Yellow" }
        "Info"     { "Cyan" }
        default    { "Gray" }
    }

    if ($Check) {
        Write-Host "  [$Severity] ($Check) $Message" -ForegroundColor $fg
    } else {
        Write-Host "  [$Severity] $Message" -ForegroundColor $fg
    }

    # SARIF result
    $sarifResults.Add([pscustomobject]@{
        ruleId  = $RuleId
        level   = (Get-SarifLevelFromSeverity -Severity $Severity)
        message = @{
            text = if ($Check) { "[$Check] $Message" } else { $Message }
        }
        locations = @(
            @{
                physicalLocation = @{
                    artifactLocation = @{
                        uri = "https://$hostname"
                    }
                    region = @{
                        startLine = 1
                        startColumn = 1
                    }
                }
            }
        )
        properties = @{
            severity = $Severity
            host     = $hostname
            check    = $Check
        }
    }) | Out-Null
}

function New-SarifRulesFromResults {
    param(
        [Parameter(Mandatory=$true)]
        [System.Collections.Generic.List[object]]$Results
    )

    # SARIF requires the tool driver "rules" list if you want nice rendering.
    # We'll generate a distinct rule entry per ruleId we used.
    $uniqueRuleIds = $Results | ForEach-Object { $_.ruleId } | Sort-Object -Unique

    $rules = @()
    foreach ($rid in $uniqueRuleIds) {
        $rules += @{
            id = $rid
            name = $rid
            shortDescription = @{ text = "SSL/TLS security finding ($rid)" }
            fullDescription  = @{ text = "Finding emitted by the Octopus SSL/TLS security check script." }
            defaultConfiguration = @{ level = "warning" }
            properties = @{
                category = "ssl-tls"
            }
        }
    }
    return $rules
}

function Write-SarifFile {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Host,
        [Parameter(Mandatory=$true)][System.Collections.Generic.List[object]]$Results
    )

    try {
        $rules = New-SarifRulesFromResults -Results $Results

        $sarif = @{
            '$schema' = "https://json.schemastore.org/sarif-2.1.0.json"
            version   = "2.1.0"
            runs      = @(
                @{
                    tool = @{
                        driver = @{
                            name           = "Octopus SSL/TLS Security Check"
                            informationUri = "https://octopus.com"
                            rules          = $rules
                        }
                    }
                    artifacts = @(
                        @{
                            location = @{
                                uri = "https://$Host"
                            }
                        }
                    )
                    results = $Results
                }
            )
        }

        $dir = Split-Path -Parent $Path
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }

        ($sarif | ConvertTo-Json -Depth 40) | Out-File -FilePath $Path -Encoding utf8
        Write-Host "🧾 SARIF written: $Path" -ForegroundColor Green
    } catch {
        Write-Host "⚠️  Failed to write SARIF output: $_" -ForegroundColor Yellow
    }
}

# ============================================
# Check 1: Basic SSL Connection & Protocol Negotiation
# ============================================
Write-Host "`n📡 Check 1: Basic SSL Connection & Protocol Negotiation"
try {
    $request = [System.Net.WebRequest]::Create("https://$hostname")
    $request.Timeout = 15000
    $response = $request.GetResponse()
    $response.Close()
    Write-Host "✅ PASS: Successfully connected via HTTPS" -ForegroundColor Green
} catch {
    Add-Finding -Severity "Critical" -Message "Cannot establish HTTPS connection - $_" -RuleId "SSL0001" -Check "Basic HTTPS"
    $allChecksPassed = $false
}

# ============================================
# Check 2: Comprehensive Certificate Analysis
# ============================================
Write-Host "`n📜 Check 2: Comprehensive Certificate Analysis"
$sslStream = $null
$tcpClient = $null

try {
    # Set TLS protocols globally
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13

    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $tcpClient.ReceiveTimeout = 10000
    $tcpClient.SendTimeout = 10000
    $tcpClient.Connect($hostname, 443)

    $sslStream = New-Object System.Net.Security.SslStream(
        $tcpClient.GetStream(),
        $false,
        { param($sender, $certificate, $chain, $sslPolicyErrors) $true }
    )

    # Authenticate with explicit protocol support
    $sslStream.AuthenticateAsClient(
        $hostname,
        $null,
        [System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls13,
        $false
    )

    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]$sslStream.RemoteCertificate

    Write-Host "`n  📋 Certificate Details:"
    Write-Host "  Subject: $($cert.Subject)"
    Write-Host "  Issuer: $($cert.Issuer)"
    Write-Host "  Serial Number: $($cert.SerialNumber)"
    Write-Host "  Thumbprint: $($cert.Thumbprint)"
    Write-Host "  Valid From: $($cert.NotBefore)"
    Write-Host "  Valid Until: $($cert.NotAfter)"

    # Check expiration
    $daysUntilExpiry = ($cert.NotAfter - (Get-Date)).Days
    Write-Host "  Days Until Expiry: $daysUntilExpiry"

    if ($daysUntilExpiry -lt 0) {
        Add-Finding -Severity "Critical" -Message "Certificate has EXPIRED" -RuleId "SSL0101" -Check "Certificate Expiry"
        $allChecksPassed = $false
    } elseif ($daysUntilExpiry -lt 7) {
        Add-Finding -Severity "Critical" -Message "Certificate expires in less than 7 days" -RuleId "SSL0102" -Check "Certificate Expiry"
        $allChecksPassed = $false
    } elseif ($daysUntilExpiry -lt $MinCertValidityDays) {
        Add-Finding -Severity "High" -Message "Certificate expires in less than $MinCertValidityDays days" -RuleId "SSL0103" -Check "Certificate Expiry"
        if ($StrictMode) { $allChecksPassed = $false }
    } elseif ($daysUntilExpiry -lt 60) {
        Add-Finding -Severity "Medium" -Message "Certificate expires in less than 60 days" -RuleId "SSL0104" -Check "Certificate Expiry"
    } else {
        Write-Host "  ✅ Certificate validity period is acceptable" -ForegroundColor Green
    }

    # Check certificate version
    Write-Host "  Certificate Version: $($cert.Version)"
    if ($cert.Version -lt 3) {
        Add-Finding -Severity "Medium" -Message "Certificate version is $($cert.Version) (v3 recommended)" -RuleId "SSL0110" -Check "Certificate Version"
    }

    # Check signature algorithm
    $signatureAlgorithm = $cert.SignatureAlgorithm.FriendlyName
    Write-Host "  Signature Algorithm: $signatureAlgorithm"

    if ($signatureAlgorithm -match "md5") {
        Add-Finding -Severity "Critical" -Message "MD5 signature algorithm detected (completely insecure)" -RuleId "SSL0120" -Check "Signature Algorithm"
        $allChecksPassed = $false
    } elseif ($signatureAlgorithm -match "sha1") {
        Add-Finding -Severity "High" -Message "SHA-1 signature algorithm detected (deprecated)" -RuleId "SSL0121" -Check "Signature Algorithm"
        if ($StrictMode) { $allChecksPassed = $false }
    } elseif ($signatureAlgorithm -match "sha256|sha384|sha512") {
        Write-Host "  ✅ Strong signature algorithm (SHA-2 family)" -ForegroundColor Green
    }

    # Check public key algorithm and size
    $publicKey = $cert.PublicKey
    Write-Host "  Public Key Algorithm: $($publicKey.Oid.FriendlyName)"

    $keySize = $publicKey.Key.KeySize
    Write-Host "  Key Size: $keySize bits"

    if ($publicKey.Oid.FriendlyName -match "RSA") {
        if ($keySize -lt 2048) {
            Add-Finding -Severity "Critical" -Message "RSA key size is $keySize bits (minimum 2048 required)" -RuleId "SSL0130" -Check "Key Size"
            $allChecksPassed = $false
        } elseif ($keySize -lt $MinKeySize) {
            Add-Finding -Severity "High" -Message "RSA key size is $keySize bits (recommended: $MinKeySize+)" -RuleId "SSL0131" -Check "Key Size"
            if ($StrictMode) { $allChecksPassed = $false }
        } elseif ($keySize -ge 4096) {
            Write-Host "  ✅ Strong RSA key size ($keySize bits)" -ForegroundColor Green
        } else {
            Write-Host "  ✅ Acceptable RSA key size ($keySize bits)" -ForegroundColor Green
        }
    } elseif ($publicKey.Oid.FriendlyName -match "ECC|ECDSA") {
        if ($keySize -ge 256) {
            Write-Host "  ✅ Strong ECC key size ($keySize bits)" -ForegroundColor Green
        } else {
            Add-Finding -Severity "High" -Message "ECC key size is $keySize bits (256+ recommended)" -RuleId "SSL0132" -Check "Key Size"
        }
    }

    # Check Subject Alternative Names (SAN)
    Write-Host "`n  🏷️  Subject Alternative Names:"
    $sanExtension = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
    if ($sanExtension) {
        $sanString = $sanExtension.Format($false)
        $sans = $sanString -split ", " | ForEach-Object { $_.Trim() }
        foreach ($san in $sans) { Write-Host "    - $san" }

        $hostnameMatch = $sans | Where-Object { $_ -match "DNS Name=$hostname" }
        if ($hostnameMatch) {
            Write-Host "  ✅ Hostname matches certificate SAN" -ForegroundColor Green
        } else {
            Add-Finding -Severity "High" -Message "Hostname '$hostname' not found in certificate SANs" -RuleId "SSL0140" -Check "SAN / Hostname Match"
            if ($StrictMode) { $allChecksPassed = $false }
        }
    } else {
        Add-Finding -Severity "Medium" -Message "No Subject Alternative Names found (SAN extension missing)" -RuleId "SSL0141" -Check "SAN"
    }

    # Wildcard certificate info
    if ($cert.Subject -match "\*\.") {
        Add-Finding -Severity "Info" -Message "Wildcard certificate detected" -RuleId "SSL0142" -Check "Certificate Type"
    }

    # Key Usage
    Write-Host "`n  🔑 Key Usage Extensions:"
    $keyUsageExt = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Key Usage" }
    if ($keyUsageExt) { Write-Host "    Key Usage: $($keyUsageExt.Format($false))" }

    $ekuExt = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Enhanced Key Usage" }
    if ($ekuExt) {
        Write-Host "    Enhanced Key Usage: $($ekuExt.Format($false))"
        if ($ekuExt.Format($false) -notmatch "Server Authentication") {
            Add-Finding -Severity "High" -Message "Certificate missing 'Server Authentication' in Enhanced Key Usage" -RuleId "SSL0150" -Check "EKU"
        }
    }

    # Basic Constraints
    $basicConstraints = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Basic Constraints" }
    if ($basicConstraints) {
        $bcString = $basicConstraints.Format($false)
        Write-Host "    Basic Constraints: $bcString"
        if ($bcString -match "Subject Type=CA") {
            Add-Finding -Severity "Critical" -Message "Certificate is marked as CA certificate (should be end-entity)" -RuleId "SSL0160" -Check "Basic Constraints"
            $allChecksPassed = $false
        }
    }

    # CRL Distribution Points
    $crlExt = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "CRL Distribution Points" }
    if ($crlExt) {
        Write-Host "    ✅ CRL Distribution Points present" -ForegroundColor Green
    } else {
        Add-Finding -Severity "Low" -Message "No CRL Distribution Points found" -RuleId "SSL0170" -Check "CRL"
    }

    # Authority Information Access (OCSP)
    $aiaExt = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Authority Information Access" }
    if ($aiaExt) {
        Write-Host "    ✅ Authority Information Access (OCSP) present" -ForegroundColor Green

        if ($CheckOCSP) {
            Write-Host "`n  🔍 Checking OCSP Revocation Status..."
            try {
                $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
                $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
                $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
                $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag

                $chainBuilt = $chain.Build($cert)

                if ($chainBuilt) {
                    Write-Host "    ✅ Certificate is not revoked" -ForegroundColor Green
                } else {
                    foreach ($status in $chain.ChainStatus) {
                        if ($status.Status -eq [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::Revoked) {
                            Add-Finding -Severity "Critical" -Message "Certificate has been REVOKED" -RuleId "SSL0180" -Check "OCSP / Revocation"
                            $allChecksPassed = $false
                        } else {
                            Add-Finding -Severity "Info" -Message "Chain status: $($status.Status) - $($status.StatusInformation)" -RuleId "SSL0181" -Check "OCSP / Revocation"
                        }
                    }
                }

                $chain.Dispose()
            } catch {
                Add-Finding -Severity "Low" -Message "Unable to verify OCSP status: $_" -RuleId "SSL0182" -Check "OCSP / Revocation"
            }
        }
    } else {
        Add-Finding -Severity "Medium" -Message "No OCSP information found (revocation checking may be slower)" -RuleId "SSL0183" -Check "AIA / OCSP"
    }

    # Self-signed / localhost heuristic
    if ($cert.Subject -match "CN=localhost" -or $cert.Issuer -match "CN=localhost") {
        Add-Finding -Severity "Critical" -Message "Self-signed or localhost certificate detected" -RuleId "SSL0190" -Check "Certificate Trust"
        $allChecksPassed = $false
    }

} catch {
    Add-Finding -Severity "Critical" -Message "Certificate analysis failed: $_" -RuleId "SSL0199" -Check "Certificate Analysis"
    Write-Host "  Error Details: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.Exception.InnerException) {
        Write-Host "  Inner Exception: $($_.Exception.InnerException.Message)" -ForegroundColor Red
    }
    $allChecksPassed = $false
} finally {
    if ($null -ne $sslStream) {
        $sslStream.Close()
        $sslStream.Dispose()
    }
    if ($null -ne $tcpClient) {
        $tcpClient.Close()
        $tcpClient.Dispose()
    }
}

# ============================================
# Check 3: Detailed TLS Protocol & Cipher Suite Analysis
# ============================================
Write-Host "`n🔐 Check 3: TLS Protocol & Cipher Suite Analysis"

$protocols = [ordered]@{
    "SSL 3.0" = [System.Security.Authentication.SslProtocols]::Ssl3
    "TLS 1.0" = [System.Security.Authentication.SslProtocols]::Tls
    "TLS 1.1" = [System.Security.Authentication.SslProtocols]::Tls11
    "TLS 1.2" = [System.Security.Authentication.SslProtocols]::Tls12
    "TLS 1.3" = [System.Security.Authentication.SslProtocols]::Tls13
}

$supportedProtocols  = @()
$deprecatedProtocols = @()
$insecureProtocols   = @()

Write-Host "`n  Testing Protocol Support:"
foreach ($protocolName in $protocols.Keys) {
    $testTcpClient = $null
    $testSslStream = $null

    try {
        $testTcpClient = New-Object System.Net.Sockets.TcpClient
        $testTcpClient.ReceiveTimeout = 5000
        $testTcpClient.SendTimeout = 5000
        $testTcpClient.Connect($hostname, 443)

        $testSslStream = New-Object System.Net.Security.SslStream(
            $testTcpClient.GetStream(),
            $false,
            { param($sender, $certificate, $chain, $sslPolicyErrors) $true }
        )

        $testSslStream.AuthenticateAsClient($hostname, $null, $protocols[$protocolName], $false)

        $supportedProtocols += $protocolName
        $negotiatedCipher = $testSslStream.CipherAlgorithm
        $negotiatedStrength = $testSslStream.CipherStrength
        $negotiatedHash = $testSslStream.HashAlgorithm
        $negotiatedHashStrength = $testSslStream.HashStrength
        $negotiatedKeyExchange = $testSslStream.KeyExchangeAlgorithm
        $negotiatedKeyExchangeStrength = $testSslStream.KeyExchangeStrength

        if ($protocolName -eq "SSL 3.0") {
            Write-Host "  ❌ $protocolName is supported (CRITICAL - POODLE vulnerability)" -ForegroundColor Red
            Add-Finding -Severity "Critical" -Message "SSL 3.0 is enabled (vulnerable to POODLE attack)" -RuleId "SSL0200" -Check "Protocol Support"
            $insecureProtocols += $protocolName
            $allChecksPassed = $false
        } elseif ($protocolName -in @("TLS 1.0", "TLS 1.1")) {
            Write-Host "  ⚠️  $protocolName is supported (DEPRECATED)" -ForegroundColor Yellow
            Write-Host "      Cipher: $negotiatedCipher ($negotiatedStrength-bit), Hash: $negotiatedHash ($negotiatedHashStrength-bit)" -ForegroundColor Yellow
            Add-Finding -Severity "High" -Message "$protocolName is enabled (deprecated since 2021)" -RuleId "SSL0201" -Check "Protocol Support"
            $deprecatedProtocols += $protocolName
            if ($StrictMode) { $allChecksPassed = $false }
        } else {
            Write-Host "  ✅ $protocolName is supported" -ForegroundColor Green
            Write-Host "      Cipher: $negotiatedCipher ($negotiatedStrength-bit)" -ForegroundColor Gray
            Write-Host "      Hash: $negotiatedHash ($negotiatedHashStrength-bit)" -ForegroundColor Gray
            Write-Host "      Key Exchange: $negotiatedKeyExchange ($negotiatedKeyExchangeStrength-bit)" -ForegroundColor Gray

            if ($negotiatedStrength -lt 128) {
                Add-Finding -Severity "High" -Message "$protocolName using weak cipher ($negotiatedStrength-bit)" -RuleId "SSL0202" -Check "Cipher Strength"
                if ($StrictMode) { $allChecksPassed = $false }
            }

            if ($negotiatedHash -match "MD5") {
                Add-Finding -Severity "Critical" -Message "$protocolName using MD5 hash algorithm" -RuleId "SSL0203" -Check "Hash Algorithm"
                $allChecksPassed = $false
            } elseif ($negotiatedHash -match "SHA1|SHA$") {
                Add-Finding -Severity "Medium" -Message "$protocolName using SHA-1 hash algorithm" -RuleId "SSL0204" -Check "Hash Algorithm"
            }

            if ($negotiatedKeyExchangeStrength -lt 2048 -and $negotiatedKeyExchange -notmatch "ECDH|DH Ephemeral") {
                Add-Finding -Severity "Medium" -Message "$protocolName using weak key exchange ($negotiatedKeyExchangeStrength-bit)" -RuleId "SSL0205" -Check "Key Exchange"
            }
        }

    } catch {
        Write-Host "  ℹ️  $protocolName is NOT supported" -ForegroundColor Gray
    } finally {
        if ($null -ne $testSslStream) {
            $testSslStream.Close()
            $testSslStream.Dispose()
        }
        if ($null -ne $testTcpClient) {
            $testTcpClient.Close()
            $testTcpClient.Dispose()
        }
    }
}

Write-Host "`n  📊 Protocol Support Summary:"
if ($insecureProtocols.Count -gt 0) {
    Add-Finding -Severity "Critical" -Message "Insecure protocols enabled: $($insecureProtocols -join ', ')" -RuleId "SSL0210" -Check "Protocol Summary"
}
if ($deprecatedProtocols.Count -gt 0) {
    Add-Finding -Severity "High" -Message "Deprecated protocols enabled: $($deprecatedProtocols -join ', ')" -RuleId "SSL0211" -Check "Protocol Summary"
}

if ("TLS 1.2" -notin $supportedProtocols -and "TLS 1.3" -notin $supportedProtocols) {
    Add-Finding -Severity "Critical" -Message "Neither TLS 1.2 nor TLS 1.3 is supported" -RuleId "SSL0212" -Check "Protocol Summary"
    $allChecksPassed = $false
} else {
    Write-Host "  ✅ Modern TLS protocols supported" -ForegroundColor Green
}

if ("TLS 1.3" -in $supportedProtocols) {
    Write-Host "  ✅ TLS 1.3 supported (best practice)" -ForegroundColor Green
} else {
    Add-Finding -Severity "Low" -Message "TLS 1.3 not supported (recommended for optimal security)" -RuleId "SSL0213" -Check "Protocol Summary"
}

# ============================================
# Check 4: HTTP to HTTPS Redirect Analysis
# ============================================
Write-Host "`n↪️  Check 4: HTTP to HTTPS Redirect Analysis"
try {
    $httpRequest = [System.Net.WebRequest]::Create("http://$hostname")
    $httpRequest.AllowAutoRedirect = $false
    $httpRequest.Timeout = 10000

    $httpResponse = $httpRequest.GetResponse()
    $statusCode = [int]$httpResponse.StatusCode
    $location = $httpResponse.Headers["Location"]
    $httpResponse.Close()

    Write-Host "  HTTP Response Code: $statusCode"
    Write-Host "  Redirect Location: $location"

    if ($statusCode -eq 301) {
        Write-Host "  ✅ Permanent redirect (301) - Good!" -ForegroundColor Green
    } elseif ($statusCode -in @(302, 307)) {
        Add-Finding -Severity "Low" -Message "Temporary redirect ($statusCode) - consider using 301 permanent redirect" -RuleId "SSL0301" -Check "HTTP Redirect"
    } elseif ($statusCode -eq 308) {
        Write-Host "  ✅ Permanent redirect (308) - Excellent!" -ForegroundColor Green
    }

    if ($location -match "^https://") {
        Write-Host "  ✅ Redirects to HTTPS" -ForegroundColor Green
    } else {
        Add-Finding -Severity "High" -Message "HTTP does not redirect to HTTPS" -RuleId "SSL0302" -Check "HTTP Redirect"
        if ($StrictMode) { $allChecksPassed = $false }
    }

    if ($location -match "^https://$hostname/?$") {
        Write-Host "  ✅ Redirect maintains domain" -ForegroundColor Green
    }

} catch [System.Net.WebException] {
    $response = $_.Exception.Response
    if ($response) {
        $statusCode = [int]$response.StatusCode
        Write-Host "  HTTP Response Code: $statusCode"
        if ($statusCode -eq 200) {
            Add-Finding -Severity "High" -Message "HTTP accessible without redirect (should redirect to HTTPS)" -RuleId "SSL0303" -Check "HTTP Redirect"
            if ($StrictMode) { $allChecksPassed = $false }
        }
    } else {
        Add-Finding -Severity "Medium" -Message "Unable to check HTTP redirect: $_" -RuleId "SSL0304" -Check "HTTP Redirect"
    }
} catch {
    Add-Finding -Severity "Medium" -Message "Unable to check HTTP redirect: $_" -RuleId "SSL0305" -Check "HTTP Redirect"
}

# ============================================
# Check 5: Comprehensive Security Headers Analysis
# ============================================
Write-Host "`n🛡️  Check 5: Comprehensive Security Headers Analysis"
try {
    $request = [System.Net.WebRequest]::Create("https://$hostname")
    $request.Timeout = 10000
    $response = $request.GetResponse()

    Write-Host "`n  Analyzing HTTP Response Headers:"

    # HSTS
    $hsts = $response.Headers["Strict-Transport-Security"]
    if ($hsts) {
        Write-Host "  ✅ Strict-Transport-Security: $hsts" -ForegroundColor Green

        if ($hsts -match "max-age=(\d+)") {
            $maxAge = [int]$matches[1]
            $maxAgeDays = $maxAge / 86400
            Write-Host "     Max-Age: $maxAgeDays days" -ForegroundColor Gray

            if ($maxAge -lt 31536000) {
                Add-Finding -Severity "Medium" -Message "HSTS max-age is less than 1 year (recommended: 31536000 seconds)" -RuleId "SSL0401" -Check "Security Headers"
            } else {
                Write-Host "     ✅ Max-age is adequate (1+ year)" -ForegroundColor Green
            }
        }

        if ($hsts -match "includeSubDomains") {
            Write-Host "     ✅ includeSubDomains directive present" -ForegroundColor Green
        } else {
            Add-Finding -Severity "Low" -Message "HSTS missing 'includeSubDomains' directive" -RuleId "SSL0402" -Check "Security Headers"
        }

        if ($hsts -match "preload") {
            Write-Host "     ✅ preload directive present" -ForegroundColor Green
        } else {
            Add-Finding -Severity "Info" -Message "HSTS missing 'preload' directive (consider HSTS preload list)" -RuleId "SSL0403" -Check "Security Headers"
        }
    } else {
        Add-Finding -Severity "High" -Message "Strict-Transport-Security header missing (HSTS not enabled)" -RuleId "SSL0404" -Check "Security Headers"
        if ($StrictMode) { $allChecksPassed = $false }
    }

    # X-Content-Type-Options
    $xcto = $response.Headers["X-Content-Type-Options"]
    if ($xcto -eq "nosniff") {
        Write-Host "  ✅ X-Content-Type-Options: $xcto" -ForegroundColor Green
    } else {
        Add-Finding -Severity "Medium" -Message "X-Content-Type-Options header missing or incorrect (should be 'nosniff')" -RuleId "SSL0410" -Check "Security Headers"
    }

    # X-Frame-Options
    $xfo = $response.Headers["X-Frame-Options"]
    if ($xfo) {
        Write-Host "  ✅ X-Frame-Options: $xfo" -ForegroundColor Green
        if ($xfo -eq "DENY") {
            Write-Host "     ✅ Strongest setting (DENY)" -ForegroundColor Green
        } elseif ($xfo -eq "SAMEORIGIN") {
            Write-Host "     ✅ Good setting (SAMEORIGIN)" -ForegroundColor Green
        }
    } else {
        Add-Finding -Severity "Medium" -Message "X-Frame-Options header missing (clickjacking protection)" -RuleId "SSL0411" -Check "Security Headers"
    }

    # CSP
    $csp = $response.Headers["Content-Security-Policy"]
    if ($csp) {
        Write-Host "  ✅ Content-Security-Policy: Present" -ForegroundColor Green
        Write-Host "     $($csp.Substring(0, [Math]::Min(100, $csp.Length)))..." -ForegroundColor Gray

        if ($csp -match "upgrade-insecure-requests") {
            Write-Host "     ✅ 'upgrade-insecure-requests' directive present" -ForegroundColor Green
        } else {
            Add-Finding -Severity "Low" -Message "CSP missing 'upgrade-insecure-requests' directive" -RuleId "SSL0412" -Check "Security Headers"
        }

        if ($csp -match "'unsafe-inline'") {
            Add-Finding -Severity "Medium" -Message "CSP allows 'unsafe-inline' (reduces XSS protection)" -RuleId "SSL0413" -Check "Security Headers"
        }

        if ($csp -match "'unsafe-eval'") {
            Add-Finding -Severity "Medium" -Message "CSP allows 'unsafe-eval' (potential security risk)" -RuleId "SSL0414" -Check "Security Headers"
        }
    } else {
        Add-Finding -Severity "Medium" -Message "Content-Security-Policy header missing" -RuleId "SSL0415" -Check "Security Headers"
    }

    # X-XSS-Protection (deprecated)
    $xxss = $response.Headers["X-XSS-Protection"]
    if ($xxss) {
        if ($xxss -eq "0") {
            Write-Host "  ℹ️  X-XSS-Protection: 0 (disabled - acceptable if CSP is strong)" -ForegroundColor Cyan
        } else {
            Write-Host "  ℹ️  X-XSS-Protection: $xxss (legacy header)" -ForegroundColor Cyan
        }
    } else {
        Add-Finding -Severity "Info" -Message "X-XSS-Protection header missing (deprecated but harmless to include)" -RuleId "SSL0420" -Check "Security Headers"
    }

    # Referrer-Policy
    $referrer = $response.Headers["Referrer-Policy"]
    if ($referrer) {
        Write-Host "  ✅ Referrer-Policy: $referrer" -ForegroundColor Green
    } else {
        Add-Finding -Severity "Low" -Message "Referrer-Policy header missing" -RuleId "SSL0421" -Check "Security Headers"
    }

    # Permissions-Policy
    $permissions = $response.Headers["Permissions-Policy"]
    if ($permissions) {
        Write-Host "  ✅ Permissions-Policy: Present" -ForegroundColor Green
        Write-Host "     $($permissions.Substring(0, [Math]::Min(100, $permissions.Length)))..." -ForegroundColor Gray
    } else {
        $featurePolicy = $response.Headers["Feature-Policy"]
        if ($featurePolicy) {
            Write-Host "  ⚠️  Feature-Policy: Present (deprecated, use Permissions-Policy)" -ForegroundColor Yellow
            Add-Finding -Severity "Info" -Message "Feature-Policy is present but deprecated (use Permissions-Policy)" -RuleId "SSL0422" -Check "Security Headers"
        } else {
            Add-Finding -Severity "Low" -Message "Permissions-Policy header missing" -RuleId "SSL0423" -Check "Security Headers"
        }
    }

    # X-Permitted-Cross-Domain-Policies
    $crossDomain = $response.Headers["X-Permitted-Cross-Domain-Policies"]
    if ($crossDomain -eq "none") {
        Write-Host "  ✅ X-Permitted-Cross-Domain-Policies: $crossDomain" -ForegroundColor Green
    } else {
        Add-Finding -Severity "Low" -Message "X-Permitted-Cross-Domain-Policies header missing or not set to 'none'" -RuleId "SSL0424" -Check "Security Headers"
    }

    # Info disclosure headers
    $server = $response.Headers["Server"]
    if ($server) {
        Write-Host "  ⚠️  Server: $server (version disclosure)" -ForegroundColor Yellow
        if ($server -match "\d+\.\d+") {
            Add-Finding -Severity "Low" -Message "Server header discloses version information" -RuleId "SSL0430" -Check "Security Headers"
        }
    } else {
        Write-Host "  ✅ Server header not present (good for security)" -ForegroundColor Green
    }

    $xPoweredBy = $response.Headers["X-Powered-By"]
    if ($xPoweredBy) {
        Add-Finding -Severity "Low" -Message "X-Powered-By header present: $xPoweredBy (information disclosure)" -RuleId "SSL0431" -Check "Security Headers"
    } else {
        Write-Host "  ✅ X-Powered-By header not present" -ForegroundColor Green
    }

    # Cookie security (best-effort)
    $cookies = $response.Headers["Set-Cookie"]
    if ($cookies) {
        Write-Host "`n  🍪 Cookie Security Analysis:"
        $cookieArray = $cookies -split "`n"

        foreach ($cookie in $cookieArray) {
            $cookieName = ($cookie -split "=")[0]
            Write-Host "    Cookie: $cookieName"

            if ($cookie -notmatch "Secure") {
                Add-Finding -Severity "High" -Message "Cookie '$cookieName' missing Secure flag" -RuleId "SSL0440" -Check "Cookies"
            } else {
                Write-Host "      ✅ Secure flag present" -ForegroundColor Green
            }

            if ($cookie -notmatch "HttpOnly") {
                Add-Finding -Severity "Medium" -Message "Cookie '$cookieName' missing HttpOnly flag" -RuleId "SSL0441" -Check "Cookies"
            } else {
                Write-Host "      ✅ HttpOnly flag present" -ForegroundColor Green
            }

            if ($cookie -match "SameSite=(Strict|Lax|None)") {
                Write-Host "      ✅ SameSite attribute present: $($matches[1])" -ForegroundColor Green
            } else {
                Add-Finding -Severity "Medium" -Message "Cookie '$cookieName' missing SameSite attribute" -RuleId "SSL0442" -Check "Cookies"
            }
        }
    }

    $response.Close()
} catch {
    Add-Finding -Severity "Medium" -Message "Unable to check security headers: $_" -RuleId "SSL0499" -Check "Security Headers"
}

# ============================================
# Check 6: Detailed Certificate Chain Validation
# ============================================
Write-Host "`n🔗 Check 6: Detailed Certificate Chain Validation"
try {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13

    $request = [System.Net.HttpWebRequest]::Create("https://$hostname")
    $request.Timeout = 10000

    $chainIsValid = $false
    $request.ServerCertificateValidationCallback = {
        param($sender, $certificate, $chain, $sslPolicyErrors)

        $script:chainIsValid = ($sslPolicyErrors -eq [System.Net.Security.SslPolicyErrors]::None)

        if ($script:chainIsValid) {
            Write-Host "  ✅ Certificate chain is valid and trusted" -ForegroundColor Green

            if ($chain.ChainElements.Count -gt 0) {
                Write-Host "  📊 Chain depth: $($chain.ChainElements.Count) certificates" -ForegroundColor Gray

                for ($i = 0; $i -lt $chain.ChainElements.Count; $i++) {
                    $element = $chain.ChainElements[$i]
                    $c = $element.Certificate

                    if ($i -eq 0) {
                        Write-Host "    [$i] End-Entity: $($c.Subject)" -ForegroundColor Gray
                    } elseif ($i -eq ($chain.ChainElements.Count - 1)) {
                        Write-Host "    [$i] Root CA: $($c.Subject)" -ForegroundColor Gray
                    } else {
                        Write-Host "    [$i] Intermediate CA: $($c.Subject)" -ForegroundColor Gray
                    }
                }

                if ($chain.ChainElements.Count -lt 2) {
                    Add-Finding -Severity "Medium" -Message "Certificate chain appears incomplete (only $($chain.ChainElements.Count) certificate)" -RuleId "SSL0501" -Check "Chain Validation"
                }
            }
        } else {
            Write-Host "  ❌ Certificate chain validation errors: $sslPolicyErrors" -ForegroundColor Red
            $script:allChecksPassed = $false

            foreach ($element in $chain.ChainElements) {
                foreach ($status in $element.ChainElementStatus) {
                    Add-Finding -Severity "High" -Message "Chain error: $($status.Status) - $($status.StatusInformation)" -RuleId "SSL0502" -Check "Chain Validation"
                }
            }
        }

        return $true
    }

    $response = $request.GetResponse()
    $response.Close()

    if (-not $chainIsValid) {
        $allChecksPassed = $false
    }

} catch {
    Add-Finding -Severity "Critical" -Message "Certificate chain validation failed: $_" -RuleId "SSL0599" -Check "Chain Validation"
    $allChecksPassed = $false
}

# ============================================
# Final Summary with Detailed Findings Report
# ============================================
Write-Host "`n" + ("=" * 80)
Write-Host "📊 FINAL SECURITY ASSESSMENT REPORT" -ForegroundColor Cyan
Write-Host ("=" * 80)

$criticalCount = $findings.Critical.Count
$highCount     = $findings.High.Count
$mediumCount   = $findings.Medium.Count
$lowCount      = $findings.Low.Count
$infoCount     = $findings.Info.Count

Write-Host "`nFindings Summary:"
if ($criticalCount -gt 0) { Write-Host "  🔴 Critical: $criticalCount" -ForegroundColor Red }
if ($highCount -gt 0)     { Write-Host "  🟠 High: $highCount"       -ForegroundColor Red }
if ($mediumCount -gt 0)   { Write-Host "  🟡 Medium: $mediumCount"   -ForegroundColor Yellow }
if ($lowCount -gt 0)      { Write-Host "  🟢 Low: $lowCount"         -ForegroundColor Yellow }
if ($infoCount -gt 0)     { Write-Host "  ℹ️  Info: $infoCount"      -ForegroundColor Cyan }

if ($criticalCount -gt 0) {
    Write-Host "`n🔴 CRITICAL Issues (Immediate Action Required):" -ForegroundColor Red
    foreach ($finding in $findings.Critical) { Write-Host "  • $finding" -ForegroundColor Red }
}
if ($highCount -gt 0) {
    Write-Host "`n🟠 HIGH Priority Issues:" -ForegroundColor Red
    foreach ($finding in $findings.High) { Write-Host "  • $finding" -ForegroundColor Red }
}
if ($mediumCount -gt 0) {
    Write-Host "`n🟡 MEDIUM Priority Issues:" -ForegroundColor Yellow
    foreach ($finding in $findings.Medium) { Write-Host "  • $finding" -ForegroundColor Yellow }
}
if ($lowCount -gt 0) {
    Write-Host "`n🟢 LOW Priority Issues:" -ForegroundColor Yellow
    foreach ($finding in $findings.Low) { Write-Host "  • $finding" -ForegroundColor Yellow }
}
if ($infoCount -gt 0) {
    Write-Host "`nℹ️  Informational:" -ForegroundColor Cyan
    foreach ($finding in $findings.Info) { Write-Host "  • $finding" -ForegroundColor Cyan }
}

# --------------------------------------------
# SARIF write-out (always at end)
# --------------------------------------------
if ($WriteSarif) {
    Write-SarifFile -Path $SarifPath -Host $hostname -Results $sarifResults
}

Write-Host "`n" + ("=" * 80)
if ($allChecksPassed) {
    Write-Host "✅ SSL/TLS SECURITY: PASSED" -ForegroundColor Green
    Write-Host "Your SSL/TLS configuration meets security best practices." -ForegroundColor Green

    if ($mediumCount -gt 0 -or $lowCount -gt 0) {
        Write-Host "`nNote: There are some recommendations for improvement listed above." -ForegroundColor Yellow
    }

    Write-Host ""
    exit 0
} else {
    Write-Host "❌ SSL/TLS SECURITY: FAILED" -ForegroundColor Red
    Write-Host "Critical security issues detected. Please review and address the findings above." -ForegroundColor Red
    Write-Host ""
    exit 1
}
