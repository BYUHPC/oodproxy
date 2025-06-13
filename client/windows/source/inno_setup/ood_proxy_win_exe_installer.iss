; Simplified Inno Setup Script for OOD Proxy BYU Client (System-Wide Only)

#define MyAppName "OOD Proxy BYU Client"
#define MyAppVersion "1.5"
#define MyAppPublisher "BYU"
#define MyAppURL "https://rc.byu.edu"
#define StunnelURL "https://www.stunnel.org/downloads.html"
#define TurboVNCURL "https://www.turbovnc.org/Downloads.html"

[Setup]
AppId={{E8F85F3D-D6A8-44E7-A4F6-D57BA32656F4}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\OOD Proxy BYU
DisableDirPage=yes
PrivilegesRequired=admin
OutputDir=userdocs:Inno Setup Output
OutputBaseFilename=ood_proxy_byu_setup
DisableProgramGroupPage=yes
Compression=lzma
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\ood_proxy_win_client.exe

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "contents\*"; DestDir: "{app}"; Flags: recursesubdirs

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Registry]
Root: HKLM; Subkey: "SOFTWARE\Classes\.oodproxybyu"; ValueType: string; ValueData: "OODProxyBYU.Config"; Flags: uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\Classes\OODProxyBYU.Config"; ValueType: string; ValueData: "OOD Proxy BYU Config File"; Flags: uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\Classes\OODProxyBYU.Config\DefaultIcon"; ValueType: string; ValueData: """{app}\remote_access_icon.ico"""; Flags: uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\Classes\OODProxyBYU.Config\shell\open\command"; ValueType: string; ValueData: """{app}\ood_proxy_win_client.exe"" ""%1"""; Flags: uninsdeletekey

[Code]
function IsDomainJoined(): Boolean;
begin
  Result := CompareText(GetEnv('USERDOMAIN'), GetEnv('COMPUTERNAME')) <> 0;
end;

function IsStunnelInstalled(): Boolean;
begin
  Result :=
    FileExists(ExpandConstant('{autopf}\stunnel\bin\stunnel.exe')) or
    FileExists(ExpandConstant('{pf32}\stunnel\bin\stunnel.exe'));
end;

function IsTurboVNCInstalled(): Boolean;
begin
  Result :=
    FileExists(ExpandConstant('{autopf}\TurboVNC\java\VncViewer.jar')) or
    FileExists(ExpandConstant('{pf32}\TurboVNC\java\VncViewer.jar'));
end;

procedure CreateRDPPolicyKeys();
begin
  // RDP policy base keys
  RegWriteDWordValue(HKLM, 'SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation', 'AllowSavedCredentials', 1);
  RegWriteDWordValue(HKLM, 'SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation', 'AllowSavedCredentialsWhenNTLMOnly', 1);
  // Add list entries
  RegWriteStringValue(HKLM, 'SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentials', '1', 'TERMSRV/127.12.25.37');
  RegWriteStringValue(HKLM, 'SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentialsWhenNTLMOnly', '1', 'TERMSRV/127.12.25.37');
end;

function InitializeSetup(): Boolean;
begin
  if not IsStunnelInstalled() then
  begin
    MsgBox(
      'Stunnel was not found on this system. The installer looked in the following locations:'#13#10 +
      '  - C:\Program Files\stunnel\bin\stunnel.exe'#13#10 +
      '  - C:\Program Files (x86)\stunnel\bin\stunnel.exe'#13#10#13#10 +
      'Please install Stunnel AS ADMINISTRATOR for all users before running this installer.'#13#10 +
      'You can download it from:'#13#10 + '{#StunnelURL}',
      mbCriticalError, MB_OK);
    Result := False;
    Exit;
  end;

  if not IsTurboVNCInstalled() then
  begin
    MsgBox(
      'TurboVNC was not found in Program Files. VNC functionality will not work until it is installed.'#13#10 +
      'You can download it from:'#13#10 + '{#TurboVNCURL}',
      mbInformation, MB_OK);
  end;

  if IsDomainJoined() then
  begin
    CreateRDPPolicyKeys();
  end;

  Result := True;
end;

function IsKeyEmpty(SubKey: string): Boolean;
var
  I: Integer;
  ValueData: string;
begin
  Result := True;
  for I := 1 to 50 do
  begin
    if RegQueryStringValue(HKLM, SubKey, IntToStr(I), ValueData) then
    begin
      Result := False;
      break;
    end;
  end;
end;

procedure RemoveRdpEntryAndMaybeDeleteKey(SubKey: string);
var
  I: Integer;
  ValueName, ValueData: string;
begin
  for I := 1 to 50 do
  begin
    ValueName := IntToStr(I);
    if RegQueryStringValue(HKLM, SubKey, ValueName, ValueData) then
    begin
      if ValueData = 'TERMSRV/127.12.25.37' then
        RegDeleteValue(HKLM, SubKey, ValueName);
    end;
  end;

  if IsKeyEmpty(SubKey) then
    RegDeleteKeyIncludingSubkeys(HKLM, SubKey);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    RemoveRdpEntryAndMaybeDeleteKey('SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentials');
    RemoveRdpEntryAndMaybeDeleteKey('SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentialsWhenNTLMOnly');

    // Delete parent policy DWORDs if no subkeys remain
    if not RegKeyExists(HKLM, 'SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentials') then
      RegDeleteValue(HKLM, 'SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation', 'AllowSavedCredentials');

    if not RegKeyExists(HKLM, 'SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentialsWhenNTLMOnly') then
      RegDeleteValue(HKLM, 'SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation', 'AllowSavedCredentialsWhenNTLMOnly');
  end;
end;
