param (
    [Parameter(Mandatory = $true)]
    [string]$ConfigFile
)

# Set verbose output
$VerbosePreference = "Continue"

# Global variables for cleanup
$script:tempDir = $null
$script:stunnelProcess = $null
$script:credentialTarget = $null
$script:pidFilePath = $null

function Parse-ConfigFile {
    param([string]$ConfigFile)
    
    if (-not (Test-Path $ConfigFile)) {
        throw "Configuration file not found: $ConfigFile"
    }

    $config = @{}
    foreach ($line in Get-Content $ConfigFile) {
        if ($line -match '^([^=]+)=(.*)$') {
            $config[$matches[1]] = $matches[2].Trim()
        }
    }

    # Validate required fields
    $requiredFields = @("REMOTE_PROXY", "JOB", "CRT_BASE64", "KEY_BASE64", "CACRT_BASE64", "USERNAME", "PASSWORD")
    foreach ($field in $requiredFields) {
        if (-not $config.ContainsKey($field) -or [string]::IsNullOrWhiteSpace($config[$field])) {
            throw "Configuration error: $field is missing or empty."
        }
    }

    return $config
}

function Initialize-TempDirectory {
    $script:tempDir = Join-Path $env:TEMP "stunnel-$(Get-Random)"
    Write-Verbose "Creating temporary directory: $script:tempDir"
    New-Item -ItemType Directory -Force -Path $script:tempDir | Out-Null
    return $script:tempDir
}

function Initialize-Certificates {
    param($config, $tempDir)
    
    $certPath = Join-Path $tempDir "cert.pem"
    $keyPath = Join-Path $tempDir "key.pem"
    $caPath = Join-Path $tempDir "ca.pem"

    try {
        [Convert]::FromBase64String($config.CRT_BASE64) | Set-Content -Path $certPath -Encoding Byte
        [Convert]::FromBase64String($config.KEY_BASE64) | Set-Content -Path $keyPath -Encoding Byte
        [Convert]::FromBase64String($config.CACRT_BASE64) | Set-Content -Path $caPath -Encoding Byte
    }
    catch {
        throw "Failed to decode or write certificates: $_"
    }

    return @{
        CertPath = $certPath
        KeyPath = $keyPath
        CAPath = $caPath
    }
}

function Cleanup-OrphanedStunnelProcesses {
    Write-Verbose "Checking for orphaned stunnel processes from previous runs..."
    Get-ChildItem $env:TEMP -Filter "stunnel-rdp-proxy-*.pid" | ForEach-Object {
        $pidContent = Get-Content $_.FullName
        if ($pidContent -match '^\d+$') {
            $pid = [int]$pidContent
            try {
                $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
                if ($process -and $process.Name -eq "stunnel") {
                    Write-Verbose "Killing orphaned stunnel process (PID: $pid)"
                    Stop-Process -Id $pid -Force
                }
            } catch {}
        }
        # Remove the PID file
        Write-Verbose "Removing orphaned PID file: $($_.FullName)"
        Remove-Item $_.FullName -Force
    }
}

function Start-StunnelProxy {
    param($config, $certPaths)

    $localPort = Get-Random -Minimum 49152 -Maximum 65535

    # Generate stunnel config
    $stunnelConf = @"
[rdp-tunnel]
client = yes
accept = 127.0.0.1:$localPort
connect = $($config.REMOTE_PROXY)
cert = $($certPaths.CertPath)
key = $($certPaths.KeyPath)
CAfile = $($certPaths.CAPath)
verifyChain = no
sslVersion = TLSv1.2
options = NO_SSLv3
options = NO_TLSv1
"@

    $stunnelConfPath = Join-Path $script:tempDir "stunnel.conf"
    $stunnelConf | Set-Content -Path $stunnelConfPath -Encoding ASCII

    # Find stunnel executable
    $stunnelPath = $null
    
    # Check common installation paths
    $possiblePaths = @(
        "C:\Program Files (x86)\stunnel\bin\stunnel.exe",
        "C:\Program Files\stunnel\bin\stunnel.exe",
        "${env:ProgramFiles(x86)}\stunnel\bin\stunnel.exe",
        "$env:ProgramFiles\stunnel\bin\stunnel.exe"
    )
    
    # Also check if it's in PATH
    $stunnelInPath = Get-Command "stunnel.exe" -ErrorAction SilentlyContinue
    if ($stunnelInPath) {
        $possiblePaths += $stunnelInPath.Source
    }
    
    # Try each path
    foreach ($path in $possiblePaths) {
        if (Test-Path $path) {
            $stunnelPath = $path
            break
        }
    }
    
    # If still not found, check registry
    if (-not $stunnelPath) {
        $regPaths = @(
            "HKLM:\SOFTWARE\WOW6432Node\stunnel.org\stunnel",
            "HKLM:\SOFTWARE\stunnel.org\stunnel"
        )
        
        foreach ($regPath in $regPaths) {
            if (Test-Path $regPath) {
                $installDir = Get-ItemProperty -Path $regPath -Name "InstallDir" -ErrorAction SilentlyContinue
                if ($installDir -and $installDir.InstallDir) {
                    $candidatePath = Join-Path $installDir.InstallDir "bin\stunnel.exe"
                    if (Test-Path $candidatePath) {
                        $stunnelPath = $candidatePath
                        break
                    }
                }
            }
        }
    }
    
    if (-not $stunnelPath) {
        $checkedPaths = $possiblePaths -join "`n- "
        $errorMessage = @"
Stunnel not found. Please ensure Stunnel is installed correctly.

To install Stunnel:
1. Download from https://www.stunnel.org/downloads.html
2. Run the installer and follow the prompts
3. Make sure to select the option to add Stunnel to your PATH
4. Restart your computer after installation
5. Try running this application again

We checked the following locations:
- $checkedPaths

If you've installed Stunnel to a different location, consider:
- Adding the Stunnel installation directory to your system PATH, or
- Reinstalling Stunnel to one of the standard locations listed above
"@
        throw $errorMessage
    }
    
    Write-Verbose "Found Stunnel at: $stunnelPath"

    Write-Verbose "Starting Stunnel for TLS proxy on 127.0.0.1:$localPort -> $($config.REMOTE_PROXY)"
    $script:stunnelProcess = Start-Process -NoNewWindow -FilePath $stunnelPath -ArgumentList $stunnelConfPath -PassThru

    # Wait for stunnel to initialize
    Start-Sleep -Seconds 2
    if ($script:stunnelProcess.HasExited) {
        throw "Stunnel failed to start or exited immediately"
    }

    # Write PID to a file in the temp directory
    $script:pidFilePath = Join-Path $env:TEMP "stunnel-rdp-proxy-$($script:stunnelProcess.Id).pid"
    $script:stunnelProcess.Id | Out-File -FilePath $script:pidFilePath
    Write-Verbose "Created PID file: $script:pidFilePath"

    return $localPort
}

function Set-RDPCredentials {
    param($config)
    
    $script:credentialTarget = "TERMSRV/127.0.0.1"
    
    Write-Verbose "Storing new RDP credentials for $script:credentialTarget"
    cmdkey /add:$script:credentialTarget /user:$($config.USERNAME) /pass:$($config.PASSWORD)
}

function Start-RDPSession {
    param($localPort, $config)

    # Default to windowed mode (1), set to fullscreen (2) if FULLSCREEN=true
    $fullscreen = "1"
    if ($config.ContainsKey("FULLSCREEN") -and $config.FULLSCREEN -match "^(1|yes|true)$") {
        $fullscreen = "2"
    }

    $rdpContent = @"
full address:s:127.0.0.1:$localPort
username:s:$($config.USERNAME)
authentication level:i:0
prompt for credentials:i:0
screen mode id:i:$fullscreen
"@

    $rdpFile = Join-Path $script:tempDir "session.rdp"
    [System.IO.File]::WriteAllText($rdpFile, $rdpContent)

    Write-Verbose "Launching RDP session to 127.0.0.1:$localPort (Fullscreen: $fullscreen)"
    Start-Process "mstsc.exe" -ArgumentList $rdpFile -Wait
}

function Cleanup {
    if ($script:credentialTarget) {
        Write-Verbose "Removing stored credentials"
        cmdkey /delete:$script:credentialTarget
    }
    
    if ($script:stunnelProcess -and -not $script:stunnelProcess.HasExited) {
        Write-Verbose "Stopping Stunnel process (PID: $($script:stunnelProcess.Id))"
        Stop-Process -InputObject $script:stunnelProcess -Force
    }

    if ($script:pidFilePath -and (Test-Path $script:pidFilePath)) {
        Write-Verbose "Removing PID file: $script:pidFilePath"
        Remove-Item $script:pidFilePath -Force
    }

    if ($script:tempDir -and (Test-Path $script:tempDir)) {
        Write-Verbose "Removing temporary directory"
        Remove-Item $script:tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Main execution block
try {
    # Clean up any orphaned stunnel processes from previous runs
    Cleanup-OrphanedStunnelProcesses

    $config = Parse-ConfigFile -ConfigFile $ConfigFile
    $tempDir = Initialize-TempDirectory
    $certPaths = Initialize-Certificates -config $config -tempDir $tempDir
    $localPort = Start-StunnelProxy -config $config -certPaths $certPaths
    Set-RDPCredentials -config $config
    Start-RDPSession -localPort $localPort -config $config
}
catch {
    Write-Error "Error: $_"
    exit 1
}
finally {
    Cleanup
}