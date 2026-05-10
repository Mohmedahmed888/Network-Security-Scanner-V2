@echo off
echo ========================================
echo Setting up Git for GitHub
echo ========================================
echo.

REM Check if git is installed
git --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Git is not installed!
    echo Please install Git from: https://git-scm.com/download/win
    pause
    exit /b 1
)

echo Git is installed!
echo.

REM Initialize git repository
echo Step 1: Initializing Git repository...
git init
echo.

REM Add all files
echo Step 2: Adding files...
git add .
echo.

REM Create initial commit
echo Step 3: Creating initial commit...
git commit -m "Initial commit: Network Security Scanner"
echo.

echo ========================================
echo Git repository initialized!
echo.
echo Next steps:
echo 1. Go to https://github.com and create a new repository
echo 2. Copy the repository URL
echo 3. Run these commands:
echo.
echo    git remote add origin YOUR_REPO_URL
echo    git branch -M main
echo    git push -u origin main
echo.
echo Or use GitHub Desktop for easier setup!
echo ========================================
pause

