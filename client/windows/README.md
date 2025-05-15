# OOD Proxy BYU Client for Microsoft Windows

## Overview
This Windows Client provides a secure connection tunnel for Remote Desktop Protocol (RDP) and Virtual Network Computing (VNC) sessions through Open OnDemand at BYU. It uses Stunnel to create a TLS encrypted tunnel to the remote proxy server.

## Files in this Package

### `ood_proxy_byu_setup.exe`
The Windows installer for end users. This installs the client application and sets up file associations for `.oodproxybyu` files. Distribute this file to users who need to connect to systems through Open OnDemand. The installer supports installing for individual users that do not have admin rights on their Windows machines, and for admins to install the software for all users on a machine.  The files in the source directory are the source code used to create the Windows installer.  Se the README file in the source directory for more information.

## Prerequisites
- Windows 10 or later
- Stunnel for Windows https://www.stunnel.org/downloads.html
- TurboVNC https://github.com/TurboVNC/turbovnc/releases

## Using the launcher
To establish a connection to a Windows VM, start a relevant Open OnDemand job, then on the job card in "My Interactive Sessons" click "RDP" or "VNC" depending on the type of connection.  The browser will download the necessary config file.  Once the config file is downloaded, the user can click on the relevant config file, and the launcher will establish the tunnel and launch the relevant RDP or VNC connection for the user.  The user will not be prompted for a password.  The downloaded config file can only be used once for a limited time. 

### Troubleshooting
- If the connection fails, verify that Stunnel is correctly installed
- The application looks for Stunnel in standard installation locations and PATH

