# Smart YARA Rule Generator

Smart YARA Rule Generator is a Windows desktop application that helps generate, save, and test YARA rules from suspicious files. The app extracts strings from a source file, filters suspicious indicators, generates a YARA rule, detects behavior tags, saves the rule in a local SQLite database, and lets the user scan another file with the saved rule.

## Main Features

- Generate YARA rules from a suspicious source file.
- Extract ASCII, wide, and readable strings from binary files.
- Filter suspicious strings before rule generation.
- Detect malware behavior tags from indicators.
- Save generated rules in SQLite.
- Scan a second file with a saved YARA rule.
- Show match or no match scan result.
- View saved rules and scan history.
- Modern PySide6 desktop interface with splash screen, dark style, icons, and custom title bar.
- Build a portable `.exe` with PyInstaller.
- Build a normal Windows installer with Inno Setup.

## Malware Behavior Tagging

The app classifies suspicious behavior using extracted indicators.

Examples:

- Registry Run key, startup path, or `HKEY` indicator: Persistence.
- `http://`, `https://`, domain names, User-Agent, or download strings: Network / Downloader.
- `cmd.exe`, `powershell`, `wscript`, or `cscript`: Command execution.
- `VirtualAlloc`, `GetProcAddress`, `LoadLibrary`, `WriteProcessMemory`: Injection / Runtime loading.
- `CreateFile`, `WriteFile`, `DeleteFile`: File manipulation.
- Debugger, sandbox, VMware, VirtualBox, or analysis tool names: Anti-analysis suspicion.

Behavior tags are saved with generated rules and displayed again in saved rules and scan history.

## Project Flow

The main project logic is:

```text
File A
  |
  | Generate YARA rule from File A
  v
Extract strings
  |
Filter suspicious strings
  |
Detect malware behavior tags
  |
Generate YARA rule
  |
Save rule + behavior tags in SQLite
  |
Choose File B
  |
Scan File B with saved rule
  |
Show Match / No Match
  |
Save scan result in history
```

## Project Structure

```text
yara/
|
+-- main.py
+-- requirements.txt
+-- assets/
|   +-- icons/
|   |   +-- app.ico
|   |   +-- folder.svg
|   |   +-- generate.svg
|   |   +-- history.svg
|   |   +-- play.svg
|   |   +-- refresh.svg
|   |   +-- rules.svg
|   |   +-- scan.svg
|   +-- images/
|       +-- Intro.jfif
|       +-- code_panel_background.png
|
+-- core/
|   +-- file_loader.py
|   +-- string_extractor.py
|   +-- filter_engine.py
|   +-- rule_generator.py
|   +-- yara_scanner.py
|   +-- behavior_tagger.py
|   +-- controller.py
|
+-- models/
|   +-- rule.py
|   +-- scan_result.py
|   +-- analysis.py
|   +-- behavior.py
|
+-- database/
|   +-- db.py
|
+-- gui/
    +-- app.py
    +-- styles/
        +-- app_style.py
```

## Role Of Each Main Part

`main.py` starts the PySide6 application and opens the main window.

`gui/app.py` contains the desktop interface: splash screen, tabs, buttons, tables, and user actions.

`gui/styles/app_style.py` keeps the visual style separate from the GUI code.

`core/controller.py` is the coordinator. It connects file loading, string extraction, filtering, rule generation, behavior tagging, scanning, and database saving.

`core/file_loader.py` loads the selected file and returns file information.

`core/string_extractor.py` extracts readable strings from binary file data.

`core/filter_engine.py` scores and filters interesting strings.

`core/rule_generator.py` creates the YARA rule content.

`core/yara_scanner.py` validates and scans files with the YARA engine.

`core/behavior_tagger.py` detects behavior categories from suspicious strings.

`models/` contains simple data classes used to move structured data between the backend, database, and GUI.

`database/db.py` saves and reads rules, behavior tags, analysis results, and scan history from SQLite.

## Local PFE Folder Layout

During development, the full local folder is organized like this:

```text
PFE/
|
+-- yara/                 # Source code repository. This is what should go to GitHub.
+-- venvyara/             # Python virtual environment. Do not push.
+-- packege/              # PyInstaller build/dist output. Do not push.
+-- installer_project/    # Inno Setup script and installer images.
+-- installer_output/     # Final setup exe. Do not push.
+-- structureCode.png
+-- uml PFE.png
```

The source project is `PFE/yara`. The virtual environment and generated executable are outside the source project to keep GitHub clean.

## Requirements

- Windows 10 or Windows 11.
- Python 3.10 recommended.
- pip.
- PySide6.
- yara-python.
- PyYAML.
- PyInstaller for packaging.
- Inno Setup for creating the installer.

Project Python dependencies are stored in `requirements.txt`:

```text
PySide6==6.11.1
PyYAML==6.0.3
yara-python==4.5.4
```

## Setup From Source

Open PowerShell in:

```powershell
C:\Users\***\OneDrive\Desktop\PFE\yara
```

Create the virtual environment outside the repo:

```powershell
python -m venv ..\venvyara
```

Activate it:

```powershell
..\venvyara\Scripts\activate
```

Install project dependencies:

```powershell
pip install -r requirements.txt
```

Run the application:

```powershell
python main.py
```

## How To Use The App

1. Start the app.
2. Enter the author name in the splash screen.
3. Open the Generate Rule tab.
4. Choose File A, the source suspicious file.
5. Enter a rule name.
6. Click Generate Rule.
7. Check the generated YARA rule and detected behavior tags.
8. Open the Scan File tab.
9. Choose File B, the target file to test.
10. Choose a saved rule.
11. Click Scan File.
12. Read the scan result: Match or No Match.
13. Open Saved Rules or History to review previous work.

## Database

The app uses SQLite for local storage.

In the source version and packaged version, the database is saved in the user local app data folder:

```text
C:\Users\<username>\AppData\Local\SmartYaraGenerator\analysis_history.db
```

This is important because the installed app may run from `Program Files`, where normal users should not write database files. Saving in AppData makes the app work like a normal Windows desktop application.

The database stores:

- Generated rules.
- Source file information.
- Rule behavior tags.
- Scan history.
- Match or no match result.
- Matched rule names.
- Scan details.

## Test Checklist

### Automated unit tests

Install the development dependencies and run the backend test suite:

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest
```

The tests use temporary files and temporary SQLite databases. They do not open
the GUI or modify the application's real history database.

After changes, test these steps:

1. Run `python main.py`.
2. Generate a rule from a sample file.
3. Confirm the generated YARA rule appears.
4. Confirm behavior tags appear when indicators exist.
5. Refresh Saved Rules and confirm the rule appears once.
6. Scan another file with the saved rule.
7. Confirm Match or No Match appears.
8. Refresh History and confirm the scan result appears once.
9. Close and reopen the app, then confirm saved data still exists.

## Packaging Portable EXE With PyInstaller

Install PyInstaller in the packaging virtual environment:

```powershell
..\venvyara\Scripts\activate
pip install pyinstaller
```

From the source folder:

```powershell
C:\Users\***\OneDrive\Desktop\PFE\yara
```

Run:

```powershell
pyinstaller --clean -y --onefile --windowed --name SmartYaraGenerator --icon "assets\icons\app.ico" --add-data "assets;assets" --hidden-import yara --distpath "..\packege\dist" --workpath "..\packege\build" --specpath "..\packege" main.py
```

After packaging, the portable executable is created here:

```text
C:\Users\****\OneDrive\Desktop\PFE\packege\dist\SmartYaraGenerator.exe
```

`build/` is PyInstaller temporary build work.

`dist/` contains the final executable.

The `.spec` file is the PyInstaller build configuration file.

## Resource Paths For Packaging

Images and icons must work in both source mode and PyInstaller mode.

The GUI uses a resource helper:

```python
def resource_path(relative_path: str) -> Path:
    if hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / relative_path
    return Path(__file__).resolve().parents[1] / relative_path
```

This is why the PyInstaller command includes:

```powershell
--add-data "assets;assets"
```

Without this option, the packaged app can open but images and icons may be missing.

## Create Windows Installer With Inno Setup

First create the portable executable with PyInstaller.

Then install Inno Setup:

```powershell
winget install JRSoftware.InnoSetup
```

The installer project is currently outside the Git repo:

```text
C:\Users\**\OneDrive\Desktop\PFE\installer_project
```

The Inno Setup script is:

```text
C:\Users\mokht\OneDrive\Desktop\PFE\installer_project\SmartYaraGeneratorInstaller.iss
```

The script takes this executable:

```text
C:\Users\**\OneDrive\Desktop\PFE\packege\dist\SmartYaraGenerator.exe
```

And creates this installer:

```text
C:\Users\****\OneDrive\Desktop\PFE\installer_output\SmartYaraGeneratorSetup.exe
```

To compile from PowerShell:

```powershell
& "C:\Users******\AppData\Local\Programs\Inno Setup 6\ISCC.exe" "C:\Users\mokht\OneDrive\Desktop\PFE\installer_project\SmartYaraGeneratorInstaller.iss"
```

The installer creates a normal Windows application installation with:

- Program Files installation folder.
- Start Menu shortcut.
- Optional desktop shortcut.
- App icon.
- Uninstaller.
- Optional launch after install.

## What To Push To GitHub

Push the source project:

```text
C:\Users\*****\OneDrive\Desktop\PFE\yara
```

Do not push:

- `venvyara/`
- `packege/`
- `build/`
- `dist/`
- `installer_output/`
- `*.db`
- `*.sqlite`
- `__pycache__/`
- Generated `.spec` files unless you intentionally want to keep the exact PyInstaller configuration.

The final installer `.exe` should usually not be committed to the repository. If you want to share it, upload it to GitHub Releases.

If the sample `.exe` files in the source folder are only for local testing, do not commit them. Binary samples can make the repository larger and may be flagged by antivirus or GitHub scanning.

## Troubleshooting

### No module named yara

Install `yara-python` in the same virtual environment used to run the app:

```powershell
..\venvyara\Scripts\activate
pip install yara-python
python -c "import yara; print(yara.__version__)"
```

If the version prints correctly but the app still fails, VS Code is probably using a different Python interpreter. Select the interpreter from `..\venvyara\Scripts\python.exe`.

### Images or icons missing in the executable

Check that the app uses the `resource_path()` helper and rebuild with:

```powershell
--add-data "assets;assets"
```

### App icon does not update in Windows Explorer

Windows sometimes caches old icons. Rebuild with `--clean`, rename the output exe for testing, or refresh Windows icon cache.

### Database does not save in installed app

The database should save in:

```text
C:\Users\<username>\AppData\Local\SmartYaraGenerator\analysis_history.db
```

Do not save the runtime database inside `Program Files`.

### Duplicate rules or history rows

The app has database checks to avoid repeated fast-click saves. If duplicates appear, verify that the GUI button is disabled while generation or scanning is running, and check the duplicate logic in `database/db.py`.

## Security Note

This project is for malware analysis education and defensive security work. Use it only on files you are allowed to analyze. Be careful with real malware samples, and avoid pushing suspicious binaries to GitHub.

