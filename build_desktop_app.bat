@echo off
echo ========================================
echo Building Desktop Application
echo Network Security Scanner
echo ========================================
echo.

REM Create dist directory if it doesn't exist
if not exist "dist" mkdir dist

REM Check if PyInstaller is installed
python -m pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo Installing PyInstaller...
    python -m pip install pyinstaller
)

echo.
echo Step 1: Creating icon file (if needed)...
python create_icon.py

echo.
echo Step 2: Building executable...
echo.

REM Build with all necessary files
pyinstaller --clean --noconfirm ^
    --name="NetworkSecurityScanner" ^
    --onefile ^
    --windowed ^
    --icon=icon.ico ^
    --add-data "netscan\\config.py;netscan" ^
    --add-data "netscan\\reporting\\templates\\report.html;netscan\\reporting\\templates" ^
    --hidden-import=PySide6.QtCore ^
    --hidden-import=PySide6.QtGui ^
    --hidden-import=PySide6.QtWidgets ^
    --hidden-import=socket ^
    --hidden-import=subprocess ^
    --hidden-import=platform ^
    --hidden-import=re ^
    --hidden-import=threading ^
    --hidden-import=concurrent.futures ^
    -m netscan

if errorlevel 1 (
    echo.
    echo ERROR: Build failed!
    pause
    exit /b 1
)

echo.
echo Step 3: Creating desktop shortcut...
python create_desktop_shortcut.py

echo.
echo ========================================
echo Build Complete!
echo.
echo Executable: dist\NetworkSecurityScanner.exe
echo Desktop Shortcut: Created on Desktop
echo ========================================
echo.
echo You can now:
echo 1. Run dist\NetworkSecurityScanner.exe directly
echo 2. Use the shortcut on your Desktop
echo.
pause


