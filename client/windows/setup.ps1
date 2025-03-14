# Set execution policy for the current user
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

# Unblock the main script file
$mainScript = Join-Path $PSScriptRoot "ood_proxy.ps1"
Unblock-File $mainScript

# Add Windows Defender exclusion for the script (prevents false positives)
Add-MpPreference -ExclusionPath $mainScript -ErrorAction SilentlyContinue

# Check for Stunnel installation
function Test-StunnelInstallation {
    $stunnelFound = $false
    
    # Check common installation paths
    $possiblePaths = @(
        "C:\Program Files (x86)\stunnel\bin\stunnel.exe",
        "C:\Program Files\stunnel\bin\stunnel.exe",
        "${env:ProgramFiles(x86)}\stunnel\bin\stunnel.exe",
        "$env:ProgramFiles\stunnel\bin\stunnel.exe"
    )
    
    # Also check if it's in PATH
    try {
        $stunnelInPath = Get-Command "stunnel.exe" -ErrorAction SilentlyContinue
        if ($stunnelInPath) {
            Write-Host "Stunnel found in PATH: $($stunnelInPath.Source)" -ForegroundColor Green
            return $true
        }
    } catch {
        # Command not found, continue checking other methods
    }
    
    # Try each path
    foreach ($path in $possiblePaths) {
        if (Test-Path $path) {
            Write-Host "Stunnel found at: $path" -ForegroundColor Green
            return $true
        }
    }
    
    # Check registry
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
                    Write-Host "Stunnel found at: $candidatePath" -ForegroundColor Green
                    return $true
                }
            }
        }
    }
    
    return $false
}

if (-not (Test-StunnelInstallation)) {
    Write-Host "WARNING: Stunnel was not detected on this system." -ForegroundColor Yellow
    Write-Host "The OOD Proxy BYU Client requires Stunnel to function correctly." -ForegroundColor Yellow
    
    # Create formatted list of paths where we looked
    $pathsChecked = @(
        "C:\Program Files (x86)\stunnel\bin\stunnel.exe",
        "C:\Program Files\stunnel\bin\stunnel.exe",
        "${env:ProgramFiles(x86)}\stunnel\bin\stunnel.exe",
        "$env:ProgramFiles\stunnel\bin\stunnel.exe",
        "Installed locations in Windows Registry",
        "System PATH environment variable"
    )
    
    Write-Host "`nWe checked these locations:" -ForegroundColor Cyan
    foreach ($path in $pathsChecked) {
        Write-Host "- $path" -ForegroundColor Cyan
    }
    
    Write-Host "`nTo install Stunnel:" -ForegroundColor Yellow
    Write-Host "1. Download from: https://www.stunnel.org/downloads.html" -ForegroundColor Yellow
    Write-Host "2. Run the installer and follow the prompts" -ForegroundColor Yellow
    Write-Host "3. Make sure to select the option to add Stunnel to your PATH if available" -ForegroundColor Yellow
    Write-Host "4. Consider installing to one of the standard locations we check" -ForegroundColor Yellow
    Write-Host "5. Restart your computer after installation" -ForegroundColor Yellow
    
    # Optional: Prompt user if they want to open the browser to download Stunnel
    $openBrowser = Read-Host "`nWould you like to open the Stunnel download page now? (Y/N)"
    if ($openBrowser -eq 'Y' -or $openBrowser -eq 'y') {
        Start-Process "https://www.stunnel.org/downloads.html"
    }
}

Write-Host "`nSetup complete!" -ForegroundColor Green
Write-Host "You can now open .oodproxybyu files to establish remote connections." -ForegroundColor Green
Write-Host "Press any key to exit..." -ForegroundColor Cyan
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
