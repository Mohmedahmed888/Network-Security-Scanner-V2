@echo off
echo ========================================
echo Building Network Security Scanner
echo ========================================
echo.

REM Check if PyInstaller is installed
python -m pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo Installing PyInstaller...
    python -m pip install pyinstaller
)

echo.
echo Creating executable...
echo.

REM Build the executable
pyinstaller --name="NetworkSecurityScanner" ^
    --onefile ^
    --windowed ^
    --icon=icon.ico ^
    --add-data "netscan\\config.py;netscan" ^
    --add-data "netscan\\reporting\\templates\\report.html;netscan\\reporting\\templates" ^
    --hidden-import=PySide6.QtCore ^
    --hidden-import=PySide6.QtGui ^
    --hidden-import=PySide6.QtWidgets ^
    -m netscan

echo.
echo ========================================
echo Build Complete!
echo Executable location: dist\NetworkSecurityScanner.exe
echo ========================================
pause


