; Inno Setup Script for OOD Proxy BYU Client
#define MyAppName "OOD Proxy BYU Client"
#define MyAppVersion "1.0"
#define MyAppPublisher "BYU"
#define MyAppURL "https://byu.edu"
#define StunnelURL "https://www.stunnel.org/downloads.html"

[Setup]
AppId={{E8F85F3D-D6A8-44E7-A4F6-D57BA32656F4}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
PrivilegesRequired=lowest
OutputDir=userdocs:Inno Setup Examples Output
OutputBaseFilename=ood_proxy_byu_setup
DefaultDirName={localappdata}\OOD Proxy BYU
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\uninstall.ico
Compression=lzma
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; Main script file
Source: "ood_proxy.ps1"; DestDir: "{app}"; Flags: ignoreversion
; PowerShell setup script to run during installation
Source: "setup.ps1"; DestDir: "{app}"; Flags: ignoreversion deleteafterinstall

[Registry]
; File association for .oodproxybyu
Root: HKCU; Subkey: "SOFTWARE\Classes\.oodproxybyu"; ValueType: string; ValueName: ""; ValueData: "OODProxyBYU.Config"; Flags: uninsdeletekey
Root: HKCU; Subkey: "SOFTWARE\Classes\OODProxyBYU.Config"; ValueType: string; ValueName: ""; ValueData: "OOD Proxy BYU Config File"; Flags: uninsdeletekey
Root: HKCU; Subkey: "SOFTWARE\Classes\OODProxyBYU.Config\shell\open\command"; ValueType: string; ValueName: ""; ValueData: "powershell.exe -ExecutionPolicy Bypass -File ""{app}\ood_proxy.ps1"" ""%1"""; Flags: uninsdeletekey

[Code]
function IsStunnelInstalled(): Boolean;
var
  StunnelPaths: array of string;
  I: Integer;
  RegKey: string;
  InstallDir: string;
  CandidatePath: string;
begin
  Result := False;
  
  // Define possible Stunnel paths
  SetArrayLength(StunnelPaths, 4);
  StunnelPaths[0] := ExpandConstant('{pf32}\stunnel\bin\stunnel.exe');
  StunnelPaths[1] := ExpandConstant('{pf}\stunnel\bin\stunnel.exe');
  StunnelPaths[2] := ExpandConstant('{pf32}\stunnel\stunnel.exe');
  StunnelPaths[3] := ExpandConstant('{pf}\stunnel\stunnel.exe');
  
  // Check direct paths
  for I := 0 to GetArrayLength(StunnelPaths) - 1 do
  begin
    if FileExists(StunnelPaths[I]) then
    begin
      Result := True;
      Exit;
    end;
  end;
  
  // Check registry for installation directory (64-bit)
  RegKey := 'SOFTWARE\WOW6432Node\stunnel.org\stunnel';
  if RegQueryStringValue(HKEY_LOCAL_MACHINE, RegKey, 'InstallDir', InstallDir) then
  begin
    CandidatePath := InstallDir + '\bin\stunnel.exe';
    if FileExists(CandidatePath) then
    begin
      Result := True;
      Exit;
    end;
  end;
  
  // Check registry for installation directory (32-bit)
  RegKey := 'SOFTWARE\stunnel.org\stunnel';
  if RegQueryStringValue(HKEY_LOCAL_MACHINE, RegKey, 'InstallDir', InstallDir) then
  begin
    CandidatePath := InstallDir + '\bin\stunnel.exe';
    if FileExists(CandidatePath) then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

function InitializeSetup(): Boolean;
var
  ErrorCode: Integer;
  PathsChecked: string;
begin
  Result := True;
  
  // Check for Stunnel installation
  if not IsStunnelInstalled() then
  begin
    // Create a message showing the paths we checked
    PathsChecked := 'We checked these standard locations:' + #13#10;
    PathsChecked := PathsChecked + '- ' + ExpandConstant('{pf32}\stunnel\bin\stunnel.exe') + #13#10;
    PathsChecked := PathsChecked + '- ' + ExpandConstant('{pf}\stunnel\bin\stunnel.exe') + #13#10;
    PathsChecked := PathsChecked + '- ' + ExpandConstant('{pf32}\stunnel\stunnel.exe') + #13#10;
    PathsChecked := PathsChecked + '- ' + ExpandConstant('{pf}\stunnel\stunnel.exe') + #13#10;
    PathsChecked := PathsChecked + '- Registry installation paths' + #13#10 + #13#10;
    PathsChecked := PathsChecked + 'If you install to a different location, please ensure Stunnel is added to your system PATH.';
    
    if MsgBox('Stunnel is required but not found.' + #13#10 + #13#10 +
              PathsChecked + #13#10 + #13#10 +
              'Would you like to download and install Stunnel now?' + #13#10 +
              '(The OOD Proxy BYU Client installation will continue after Stunnel is installed)',
              mbConfirmation, MB_YESNO) = IDYES then
    begin
      // Open Stunnel download page in default browser
      if not ShellExec('open', '{#StunnelURL}', '', '', SW_SHOWNORMAL, ewNoWait, ErrorCode) then
      begin
        MsgBox('Could not open the Stunnel download page. Please visit {#StunnelURL} manually.', mbError, MB_OK);
      end;
      // Let user know they need to run this installer again after installing Stunnel
      MsgBox('Please install Stunnel, then run this installer again.' + #13#10 + #13#10 +
             'Installation Tips:' + #13#10 +
             '1. Select the option to add Stunnel to your PATH if available' + #13#10 +
             '2. Install to one of the standard locations we check' + #13#10 +
             '3. Restart your computer after installation', 
             mbInformation, MB_OK);
      Result := False;
    end
    else
    begin
      Result := False;
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    // Clean up registry entries (in case any were missed)
    RegDeleteKeyIncludingSubkeys(HKEY_CURRENT_USER, 'SOFTWARE\Classes\.oodproxybyu');
    RegDeleteKeyIncludingSubkeys(HKEY_CURRENT_USER, 'SOFTWARE\Classes\OODProxyBYU.Config');
  end;
end;