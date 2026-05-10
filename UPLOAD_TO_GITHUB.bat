@echo off
echo ========================================
echo Upload Project to GitHub
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

echo Step 1: Initializing Git...
if not exist .git (
    git init
    echo Git repository initialized.
) else (
    echo Git repository already exists.
)
echo.

echo Step 2: Adding all files...
git add .
echo.

echo Step 3: Creating commit...
git commit -m "Initial commit: Network Security Scanner - Advanced Network Monitor"
echo.

echo ========================================
echo Local Git setup complete!
echo.
echo Now you need to:
echo.
echo 1. Go to https://github.com and login
echo 2. Click the "+" button (top right) ^> "New repository"
echo 3. Enter repository name (e.g., network-security-scanner)
echo 4. Choose Public or Private
echo 5. DO NOT check "Initialize with README"
echo 6. Click "Create repository"
echo.
echo 7. After creating, copy the repository URL
echo    (it will look like: https://github.com/username/repo-name.git)
echo.
echo 8. Then run these commands:
echo.
echo    git remote add origin YOUR_REPO_URL_HERE
echo    git branch -M main
echo    git push -u origin main
echo.
echo Or use GitHub Desktop for easier setup!
echo ========================================
echo.
echo Press any key to continue...
pause >nul

echo.
echo Enter your GitHub repository URL (or press Enter to skip):
set /p REPO_URL="Repository URL: "

if not "%REPO_URL%"=="" (
    echo.
    echo Adding remote repository...
    git remote add origin %REPO_URL% 2>nul
    if errorlevel 1 (
        git remote set-url origin %REPO_URL%
        echo Remote URL updated.
    ) else (
        echo Remote repository added.
    )
    
    echo.
    echo Setting branch to main...
    git branch -M main
    
    echo.
    echo Pushing to GitHub...
    git push -u origin main
    
    if errorlevel 1 (
        echo.
        echo ERROR: Push failed!
        echo Make sure:
        echo - The repository URL is correct
        echo - You have access to the repository
        echo - You're logged in to GitHub
        echo.
        echo You may need to authenticate. Try:
        echo   git push -u origin main
    ) else (
        echo.
        echo ========================================
        echo SUCCESS! Project uploaded to GitHub!
        echo ========================================
    )
) else (
    echo.
    echo Skipped. You can add the remote later using:
    echo   git remote add origin YOUR_REPO_URL
    echo   git push -u origin main
)

echo.
pause

