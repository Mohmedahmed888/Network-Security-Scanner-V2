@echo off
echo ========================================
echo Push Project to GitHub
echo ========================================
echo.
echo The local repository is already initialized!
echo.
echo Now you need to:
echo.
echo 1. Create a repository on GitHub (if you haven't already)
echo    Go to: https://github.com/new
echo.
echo 2. After creating, copy the repository URL
echo    (Example: https://github.com/username/repo-name.git)
echo.
echo 3. Enter the URL below:
echo.
set /p REPO_URL="Enter GitHub Repository URL: "

if "%REPO_URL%"=="" (
    echo.
    echo No URL provided. Exiting.
    pause
    exit /b 1
)

echo.
echo Adding remote repository...
git remote add origin %REPO_URL% 2>nul
if errorlevel 1 (
    git remote set-url origin %REPO_URL%
    echo Remote URL updated to: %REPO_URL%
) else (
    echo Remote repository added: %REPO_URL%
)

echo.
echo Setting branch to main...
git branch -M main

echo.
echo Pushing to GitHub...
echo (You may be asked to login/authenticate)
echo.
git push -u origin main

if errorlevel 1 (
    echo.
    echo ========================================
    echo Push failed!
    echo.
    echo Possible reasons:
    echo - Authentication required (GitHub login)
    echo - Repository URL is incorrect
    echo - Network connection issue
    echo.
    echo Solutions:
    echo 1. Make sure you're logged in to GitHub
    echo 2. Check the repository URL
    echo 3. Try using GitHub Desktop for easier push
    echo ========================================
) else (
    echo.
    echo ========================================
    echo SUCCESS! Project pushed to GitHub!
    echo ========================================
    echo.
    echo Your project is now live at:
    echo %REPO_URL%
    echo.
)

pause

