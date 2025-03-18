# Launcher script for Linux

This directory contains the script for launching socat to connect to OODProxy
and launch a VNC/RDP client to connect to the socat instance.

The script is located at
- `oodproxy-launcher-byu/usr/sbin/oodproxy-launcher-byu`

There are also .desktop and .xml files to associate the script with the correct
extension and MIME types.  Thy are located at:
- `oodproxy-launcher-byu/usr/share/applications/oodproxy-launcher.desktop`
- `oodproxy-launcher-byu/usr/share/mime/packages/oodproxybyu.xml`

`oodproxy-launcher-build` is a script to build a .deb package for Debian/Ubuntu.

A .deb package is included in the repo.  At some point we would like to create
an actual repo for this and for .rpm packages.  Hopefully soon...
