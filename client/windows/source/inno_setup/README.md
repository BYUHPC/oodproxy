To build the Windows installer:

Build the C# project.  The C# project should build in a folder such as <project folder>/bin/Release/net8.0-windows/win-x64/publish/.   See C# README for more iformation on building the C# project.

Copy the contents of the compiled C# code in the "publish" folder to the Windows computer that will be used to create the inno installer to distribute to your users.

Rename the downloaded "publish" folder to "contents" as specified in the inno setup code.

Copy the provided icon, remote_access_icon.ico, from this github repository folder to the "contents" folder.  That way the icon will be distributed with the installer.

Open the Inno Setup IDE and open the included ood_proxy_win_exe_installer.

Build the inno project.

Test the compiled installer.  It will be located in the configured "inno setup output" folder.  
