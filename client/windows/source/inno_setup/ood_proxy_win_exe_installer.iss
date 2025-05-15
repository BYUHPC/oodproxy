; Inno Setup Script for OOD Proxy BYU Client with dynamic scope selection
#define MyAppName "OOD Proxy BYU Client"
#define MyAppVersion "1.1"
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
DisableDirPage=yes
DefaultDirName={code:GetInstallDir}
PrivilegesRequired=lowest
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
Type: filesandordirs; Name: "{localappdata}\OOD Proxy BYU"
Type: dirifempty; Name: "{localappdata}\OOD Proxy BYU"

[Registry]
; Per-user registry entries
Root: HKCU; Check: IsPerUserInstall; Subkey: "SOFTWARE\Classes\.oodproxybyu"; ValueType: string; ValueData: "OODProxyBYU.Config"; Flags: uninsdeletekey
Root: HKCU; Check: IsPerUserInstall; Subkey: "SOFTWARE\Classes\OODProxyBYU.Config"; ValueType: string; ValueData: "OOD Proxy BYU Config File"; Flags: uninsdeletekey
Root: HKCU; Check: IsPerUserInstall; Subkey: "SOFTWARE\Classes\OODProxyBYU.Config\DefaultIcon"; ValueType: string; ValueData: """{app}\remote_access_icon.ico"""; Flags: uninsdeletekey
Root: HKCU; Check: IsPerUserInstall; Subkey: "SOFTWARE\Classes\OODProxyBYU.Config\shell\open\command"; ValueType: string; ValueData: """{app}\ood_proxy_win_client.exe"" ""%1"""; Flags: uninsdeletekey

; All-users registry entries
Root: HKLM; Check: IsPerMachineInstall; Subkey: "SOFTWARE\Classes\.oodproxybyu"; ValueType: string; ValueData: "OODProxyBYU.Config"; Flags: uninsdeletekey
Root: HKLM; Check: IsPerMachineInstall; Subkey: "SOFTWARE\Classes\OODProxyBYU.Config"; ValueType: string; ValueData: "OOD Proxy BYU Config File"; Flags: uninsdeletekey
Root: HKLM; Check: IsPerMachineInstall; Subkey: "SOFTWARE\Classes\OODProxyBYU.Config\DefaultIcon"; ValueType: string; ValueData: """{app}\remote_access_icon.ico"""; Flags: uninsdeletekey
Root: HKLM; Check: IsPerMachineInstall; Subkey: "SOFTWARE\Classes\OODProxyBYU.Config\shell\open\command"; ValueType: string; ValueData: """{app}\ood_proxy_win_client.exe"" ""%1"""; Flags: uninsdeletekey


[Code]
var
  InstallScopePage: TInputOptionWizardPage;
  IsPerMachine: Boolean;
    
function GetRegistryRoot(Default: string): string;
begin
  if IsPerMachine then
    Result := 'HKLM'
  else
    Result := 'HKCU';
end;

function IsPerMachineInstall(): Boolean;
begin
  Result := IsPerMachine;
end;

function IsPerUserInstall(): Boolean;
begin
  Result := not IsPerMachine;
end;

function GetInstallDir(Default: string): string;
begin
  // Called at setup load time; use a fallback guess here
  if IsPerMachine then
    Result := ExpandConstant('{pf}\OOD Proxy BYU')
  else
    Result := ExpandConstant('{localappdata}\OOD Proxy BYU');
end;

procedure InitializeWizard;
begin
  InstallScopePage := CreateInputOptionPage(
    wpWelcome,
    'Install Scope',
    'Choose who should be able to use this software:',
    'Select exactly one option below:',
    True,  // <-- Exclusive = True (radio button behavior)
    False  // Don't allow "Back" to be skipped
  );
  InstallScopePage.Add('All users (requires admin)');
  InstallScopePage.Add('Just me (no admin required)');
  InstallScopePage.SelectedValueIndex := 1; // default to "Just me"
end;

procedure UpdateInstallDir;
begin
  WizardForm.DirEdit.Text := GetInstallDir('');
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;

  if CurPageID = InstallScopePage.ID then
  begin
    IsPerMachine := (InstallScopePage.SelectedValueIndex = 0);

    if IsPerMachine and not IsAdminLoggedOn then
    begin
      MsgBox('Administrative privileges are required to install for all users. Please restart this installer as administrator.', mbError, MB_OK);
      Result := False;
      Exit;
    end;

    // 👇 This updates the directory textbox to reflect the selected scope
    UpdateInstallDir;

    if IsPerMachine then
      Log('Install scope selected: All users; Target dir: ' + GetInstallDir(''))
    else
      Log('Install scope selected: Just me; Target dir: ' + GetInstallDir(''));
  end;
end;

function IsStunnelInstalled(): Boolean;
begin
  Result := FileExists(ExpandConstant('{pf32}\stunnel\bin\stunnel.exe')) or
            FileExists(ExpandConstant('{pf}\stunnel\bin\stunnel.exe')) or
            FileExists(ExpandConstant('{localappdata}\Programs\stunnel\bin\stunnel.exe')) or
            FileExists(ExpandConstant('{localappdata}\stunnel\bin\stunnel.exe'));
end;

function IsTurboVNCInstalled(): Boolean;
begin
  Result := FileExists(ExpandConstant('{pf}\TurboVNC\java\VncViewer.jar')) or
            FileExists(ExpandConstant('{localappdata}\TurboVNC\java\VncViewer.jar'));
end;

function InitializeSetup(): Boolean;
var
  ErrorCode: Integer;
begin
  // Set a default guess before wizard UI runs
  IsPerMachine := IsAdminLoggedOn;
  Result := True;

  if not IsStunnelInstalled() then
  begin
    if MsgBox(
         'Stunnel is required but was not found.'#13#10#13#10 +
         'Would you like to open the Stunnel download page?',
         mbConfirmation, MB_YESNO) = IDYES then
    begin
      ShellExec('open', '{#StunnelURL}', '', '', SW_SHOWNORMAL, ewNoWait, ErrorCode);
    end;

    MsgBox(
      'Please install Stunnel before using this application.'#13#10 +
      'The installer will continue, but the app may not function without it.',
      mbInformation, MB_OK);
  end;

  if not IsTurboVNCInstalled() then
  begin
    MsgBox(
      'TurboVNC was not found.'#13#10#13#10 +
      'VNC connections will not work until it is installed.'#13#10 +
      'You can download it from:'#13#10 + '{#TurboVNCURL}',
      mbInformation, MB_OK);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    RegDeleteKeyIncludingSubkeys(HKEY_CURRENT_USER, 'SOFTWARE\Classes\.oodproxybyu');
    RegDeleteKeyIncludingSubkeys(HKEY_CURRENT_USER, 'SOFTWARE\Classes\OODProxyBYU.Config');
  end;
end;
