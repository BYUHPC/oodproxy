; Installer B: OOD Proxy Credential Policy Installer
#define MyAppName "OOD Proxy Policy Installer For Domain Clients"
#define MyAppVersion "1.0"
#define MyAppPublisher "BYU"

[Setup]
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={tmp}\{#MyAppName}
DisableDirPage=yes
DisableProgramGroupPage=yes
OutputBaseFilename=ood_proxy_policy_installer
OutputDir=userdocs:Inno Setup Output
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Registry]
; Credential Delegation policy keys for domain-joined machines only
Root: HKLM; Check: IsDomainJoined; Subkey: "SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"; Flags: uninsdeletekeyifempty
Root: HKLM; Check: IsDomainJoined; Subkey: "SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"; ValueType: dword; ValueName: "AllowSavedCredentials"; ValueData: 1
Root: HKLM; Check: IsDomainJoined; Subkey: "SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"; ValueType: dword; ValueName: "AllowSavedCredentialsWhenNTLMOnly"; ValueData: 1
Root: HKLM; Check: IsDomainJoined; Subkey: "SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentials"; ValueType: string; ValueName: "1"; ValueData: "TERMSRV/127.12.25.37"
Root: HKLM; Check: IsDomainJoined; Subkey: "SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowSavedCredentialsWhenNTLMOnly"; ValueType: string; ValueName: "1"; ValueData: "TERMSRV/127.12.25.37"

[Code]
function IsDomainJoined(): Boolean;
begin
  Result := CompareText(GetEnv('USERDOMAIN'), GetEnv('COMPUTERNAME')) <> 0;
end;

function InitializeSetup(): Boolean;
begin
 if MsgBox(
    'This installer adds an exception to your local machine to allow saved credentials when connecting to the remote system running on the HPC cluster.'#13#10#13#10 +
    'Specifically, it enables a policy exception for one IP address (127.12.25.37) so that the temporary credentials downloaded by your browser can be used by your RDP client.'#13#10#13#10 +
    'On domain-joined machines, saved credentials are normally blocked to enforce the use of domain authentication. This installer safely enables that exception for this specific case only.'#13#10#13#10 +
    'There is no uninstaller provided for this policy exception.'#13#10#13#10 +
    'Click OK to proceed and apply the policy. Click Cancel to exit without making changes.',
    mbInformation, MB_OKCANCEL) <> IDOK then
  begin
    Result := False;
    Exit;
  end;
  if not IsDomainJoined() then
  begin
    MsgBox('This machine is not joined to a domain. This installer is only for domain-joined systems.', mbInformation, MB_OK);
    Result := False;
    Exit;
  end;
  Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    MsgBox('Credential delegation policy has been installed successfully.', mbInformation, MB_OK);
  end;
end;
