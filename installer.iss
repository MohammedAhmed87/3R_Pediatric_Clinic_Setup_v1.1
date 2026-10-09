; Script generated for 3R Software Solutions
#define MyAppName "3R Pediatric Arrhythmia Clinic System"
#define MyAppVersion "1.1.0"
#define MyAppPublisher "3R Software Solutions"
#define MyAppExeName "desktop_app.exe"
#define MyAppIcon "logo.ico"

[Setup]
AppId={{266E4AE6-0929-4F28-BBAB-B80B2452A116}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\3R Software Solutions\Pediatric Clinic System
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=Output
OutputBaseFilename=3R_Pediatric_Clinic_Setup_v1.1
SetupIconFile={#MyAppIcon}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
; تضمين جميع ملفات ومجلدات تطبيقك من dist/desktop_app
Source: "dist\desktop_app\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppIcon}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppIcon}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent