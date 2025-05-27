<#
.SYNOPSIS
    Checks if an SSH service is listening on a specified port and attempts to determine its SSH protocol version (v1 or v2).

.DESCRIPTION
    This script connects to a target host and port (defaulting to 22 for SSH).
    It first establishes a raw TCP connection to determine if the port is open.
    If successful, it then proceeds to read the SSH banner, which typically
    indicates the SSH protocol version (e.g., "SSH-2.0-OpenSSH_8.2p1").

.PARAMETER Hostname
    The hostname or IP address of the target server to check.

.PARAMETER Port
    The port number to check for the SSH service. Defaults to 22.

.EXAMPLE
    .\Check-SshServiceAndVersion.ps1 -Hostname "yourserver.com" -Port 22
    Checks SSH on port 22 for 'yourserver.com'.

.EXAMPLE
    "192.168.1.10", "anotherhost" | .\Check-SshServiceAndVersion.ps1
    Pipes multiple hostnames to the script, checking SSH on default port 22 for each.

.NOTES
    - This script relies on reading the SSH banner. Some SSH servers might not
      provide a clear banner, or might delay it, which could affect detection.
    - It distinguishes between SSHv1 and SSHv2 based on the "SSH-1.x" or "SSH-2.x"
      prefix in the banner.
    - Requires network connectivity to the target host and port.
    - The initial port listening check now uses a direct TcpClient connection
      for improved reliability over Test-NetConnection in some environments.
#>
[CmdletBinding(DefaultParameterSetName='Default')]
param(
    [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
    [string]$Hostname,

    [Parameter(Mandatory=$false, Position=1)]
    [int]$Port = 22
)

process {
    Write-Verbose "Checking SSH service on $($Hostname):$($Port)"

    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $stream = $null
    $streamReader = $null
    $portIsListening = $false

    try {
        # Attempt to connect directly to determine if the port is listening
        $connectTask = $tcpClient.ConnectAsync($Hostname, $Port)
        $connectTask.Wait(5000) # Wait up to 5 seconds for connection

        if ($tcpClient.Connected) {
            $portIsListening = $true
            Write-Host "SSH port $($Port) is listening on $($Hostname)." -ForegroundColor Green

            Write-Verbose "TCP connection established to read banner."

            $stream = $tcpClient.GetStream()
            $streamReader = New-Object System.IO.StreamReader($stream)

            # Set a timeout for reading the banner (e.g., 5 seconds)
            $stream.ReadTimeout = 5000

            # Read the first line, which should be the SSH banner
            $sshBanner = $streamReader.ReadLine()

            if (-not [string]::IsNullOrEmpty($sshBanner)) {
                Write-Host "SSH Banner: $($sshBanner)" -ForegroundColor Cyan

                if ($sshBanner -match "^SSH-2\.0-") {
                    Write-Host "SSH Protocol Version: SSHv2 is operating." -ForegroundColor Green
                } elseif ($sshBanner -match "^SSH-1\.") {
                    Write-Host "SSH Protocol Version: SSHv1 is operating." -ForegroundColor Yellow
                    Write-Warning "SSHv1 is an older, less secure protocol and should be avoided."
                } else {
                    Write-Host "SSH Protocol Version: Unable to determine (non-standard banner or other protocol)." -ForegroundColor Yellow
                }
            } else {
                Write-Host "SSH Banner: No banner received or empty banner." -ForegroundColor Yellow
            }
        } else {
            Write-Host "SSH port $($Port) is NOT listening on $($Hostname)." -ForegroundColor Red
        }
    }
    catch {
        # Catch specific connection errors
        if ($_.Exception.InnerException -is [System.Net.Sockets.SocketException]) {
            Write-Host "SSH port $($Port) is NOT listening on $($Hostname). Error: $($_.Exception.InnerException.Message)" -ForegroundColor Red
        } else {
            Write-Warning "An error occurred during SSH check on $($Hostname):$($Port). Error: $($_.Exception.Message)"
        }
    }
    finally {
        # Ensure resources are cleaned up
        if ($streamReader) { $streamReader.Dispose() }
        if ($stream) { $stream.Dispose() }
        if ($tcpClient) { $tcpClient.Close() }
    }
}
