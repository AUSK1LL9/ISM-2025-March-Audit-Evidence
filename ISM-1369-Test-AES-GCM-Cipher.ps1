function Get-RemoteTlsCipherSuite {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$TargetHost,

        [Parameter(Position=1)]
        [int]$TargetPort = 443,

        [Parameter(Position=2)]
        [System.Security.Authentication.SslProtocols]$TlsProtocol = ([System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls13),

        [Parameter(Position=3)]
        [switch]$SkipCertificateValidation # New parameter to control validation
    )

    # Check if System.Net.Security types are already loaded before adding the assembly
    if (-not ([System.Net.Security.SslStream])) {
        try {
            Add-Type -AssemblyName System.Net.Security -ErrorAction Stop
        }
        catch {
            Write-Warning "Could not load System.Net.Security assembly. Ensure your PowerShell environment is compatible. Error: $($_.Exception.Message)"
            # If the assembly truly cannot be loaded, the SslStream New-Object call will fail later.
        }
    }

    # Check if System.Security.Cryptography.X509Certificates types are already loaded before adding the assembly
    if (-not ([System.Security.Cryptography.X509Certificates.X509Certificate2])) {
        try {
            Add-Type -AssemblyName System.Security.Cryptography.X509Certificates -ErrorAction Stop
        }
        catch {
            Write-Warning "Could not load System.Security.Cryptography.X509Certificates assembly. Ensure your PowerShell environment is compatible. Error: $($_.Exception.Message)"
        }
    }

    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $sslStream = $null

    try {
        # Corrected variable reference: ${TargetHost}:${TargetPort}
        Write-Verbose "Connecting to ${TargetHost}:${TargetPort}..."
        $tcpClient.Connect($TargetHost, $TargetPort)

        # Define the certificate validation callback
        # This callback will always return true if $SkipCertificateValidation is set
        $certValidationCallback = {
            param($sender, $certificate, $chain, $sslPolicyErrors)
            if ($SkipCertificateValidation) {
                return $true # Bypass certificate validation
            }
            # Otherwise, use default validation (return true only if no errors)
            return ($sslPolicyErrors -eq [System.Net.Security.SslPolicyErrors]::None)
        }

        # Create SslStream with the custom validation callback
        $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, $certValidationCallback)

        Write-Verbose "Performing TLS handshake..."
        # AuthenticateAsClient now uses the custom validation callback
        $sslStream.AuthenticateAsClient($TargetHost, $null, $TlsProtocol, $false)

        $cipherSuiteName = $sslStream.CipherAlgorithm.ToString()
        $hashAlgorithmName = $sslStream.HashAlgorithm.ToString()
        $keyExchangeAlgorithmName = $sslStream.KeyExchangeAlgorithm.ToString()
        $tlsProtocolUsed = $sslStream.SslProtocol.ToString()

        [PSCustomObject]@{
            TargetHost = $TargetHost
            TargetPort = $TargetPort
            TlsProtocolUsed = $tlsProtocolUsed
            CipherAlgorithm = $cipherSuiteName
            HashAlgorithm = $hashAlgorithmName
            KeyExchangeAlgorithm = $keyExchangeAlgorithmName
            IsAESSecured = ($cipherSuiteName -like "*Aes*")
            IsGCMUsed = ($cipherSuiteName -like "*Gcm*")
            CertificateValidationSkipped = $SkipCertificateValidation
        }
    }
    catch {
        # Corrected variable reference: ${TargetHost}:${TargetPort}
        Write-Error "Error connecting to ${TargetHost}:${TargetPort}: $($_.Exception.Message)"
        [PSCustomObject]@{
            TargetHost = $TargetHost
            TargetPort = $TargetPort
            Status = "Connection Failed"
            ErrorMessage = $_.Exception.Message
            CertificateValidationSkipped = $SkipCertificateValidation
        }
    }
    finally {
        if ($sslStream) { $sslStream.Dispose() }
        if ($tcpClient) { $tcpClient.Close() }
    }
}

# --- How to use the function to scan a remote web server ---

# Example 2: Scan multiple hosts from a list, skipping certificate validation
$serversToScan = @("vcsa8", "esx01", "esx02")

Write-Host "`nScanning multiple servers for AES-GCM (skipping certificate validation)..."
$serversToScan | ForEach-Object {
    Get-RemoteTlsCipherSuite -TargetHost $_ -TargetPort 443 -SkipCertificateValidation |
        Select-Object TargetHost, TlsProtocolUsed, CipherAlgorithm, IsAESSecured, IsGCMUsed, CertificateValidationSkipped
} | Format-Table -AutoSize

# Example 3: Combine with local check and filter for GCM
Write-Host "`nLocal AES-GCM Cipher Suites:"
Get-TlsCipherSuite | Where-Object { $_.Name -like "*_AES_*_GCM_*" } | Format-Table Name, Cipher, CipherLength, Hash, Protocols -AutoSize

Write-Host "`nRemote Server Scan Results (checking for AES-GCM, skipping validation for vcsa8.qitcs.com.au):"
Get-RemoteTlsCipherSuite -TargetHost "vcsa8.qitcs.com.au" -TargetPort 443 -SkipCertificateValidation | Where-Object { $_.IsAESSecured -and $_.IsGCMUsed } | Format-List
