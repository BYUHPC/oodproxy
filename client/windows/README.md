# OOD Proxy BYU Client for Microsoft Windows

## Overview
This application provides a secure connection tunnel for Remote Desktop Protocol (RDP) sessions through Open OnDemand at BYU. It uses Stunnel to create a TLS encrypted tunnel to the remote proxy server.

## Files in this Package

### `ood_proxy_byu_setup.exe`
The Windows installer for end users. This installs the client application and sets up file associations for `.oodproxybyu` files. Distribute this file to users who need to connect to systems through Open OnDemand.  This installer contains everything needed for installation.  The rest of the files here are the source code used to create the Windows installer.

### `ood_proxy.ps1`
The main PowerShell script that:
- Creates a secure TLS tunnel using Stunnel
- Establishes the connection to the remote server
- Launches the Microsoft Remote Desktop client (mstsc.exe)
- Manages temporary credentials and cleanup

Connection details are automatically downloaded from Open OnDemand in the `.oodproxybyu` file format, so no manual configuration of this script is typically necessary.

### `setup.ps1`
This PowerShell installation script runs during installation and:
- Associates the `.oodproxybyu` file extension with the application
- Verifies Stunnel installation and provides guidance if it's missing
- Sets necessary execution policies and security exceptions

### `installer.iss`
The Inno Setup Compiler script used to build the Windows installer. Use this with Inno Setup Compiler 6.4.0 or later if you need to modify and rebuild the installer.

## Prerequisites
- Windows 10 or later
- PowerShell 5.1 or later
- Stunnel for Windows https://www.stunnel.org/downloads.html

## Using the launcher
To establish a connection to a Windows VM, start a relevant Open OnDemand job, then on the job card in "My Interactive Sessons" click "RDP".  The browser will download the necessary config file and the launcher will run a PowerShell script that handles the rest of the session for you.  It will start stunnel and launch mstsc.exe with all of the appropriate parameters.  When the RDP window is closed, the PowerShell script will close stunnel and exit.

### Troubleshooting
- If the connection fails, verify that Stunnel is correctly installed
- For installation issues, check the Windows Event Log for PowerShell execution errors
- The application looks for Stunnel in standard installation locations and PATH

## For Developers
If you need to make changes to any components:
1. Modify the necessary files (`installer.iss`, `ood_proxy.ps1`, or `setup.ps1`)
2. Rebuild the installer using Inno Setup Compiler 6.4.0 or later
3. Test the new installer thoroughly before distribution

