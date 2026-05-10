@echo off
chcp 65001 >nul
echo ========================================
echo رفع المشروع على GitHub
echo ========================================
echo.
echo المستودع المحلي جاهز ✓
echo.
echo الآن تحتاج إلى:
echo.
echo 1. اذهب إلى https://github.com/new
echo 2. أنشئ مستودع جديد (Repository)
echo 3. انسخ رابط المستودع
echo.
echo أدخل رابط المستودع على GitHub:
echo (مثال: https://github.com/username/repo-name.git)
echo.
set /p REPO_URL="الرابط: "

if "%REPO_URL%"=="" (
    echo.
    echo ❌ لم تدخل رابط! اخرج وأعد المحاولة.
    pause
    exit /b 1
)

echo.
echo ⏳ جاري الربط بالمستودع...
git remote add origin %REPO_URL% 2>nul
if errorlevel 1 (
    git remote set-url origin %REPO_URL%
    echo ✓ تم تحديث رابط المستودع
) else (
    echo ✓ تم إضافة المستودع: %REPO_URL%
)

echo.
echo ⏳ جاري الرفع على GitHub...
echo (قد يُطلب منك تسجيل الدخول)
echo.
git push -u origin main

if errorlevel 1 (
    echo.
    echo ❌ فشل الرفع!
    echo.
    echo الأسباب المحتملة:
    echo - لم تسجل الدخول على GitHub
    echo - رابط المستودع غير صحيح
    echo - مشكلة في الاتصال
    echo.
    echo الحلول:
    echo 1. تأكد من تسجيل الدخول على GitHub
    echo 2. تحقق من رابط المستودع
    echo 3. استخدم GitHub Desktop لسهولة أكبر
    echo.
) else (
    echo.
    echo ========================================
    echo ✅ نجح! تم رفع المشروع على GitHub
    echo ========================================
    echo.
    echo المشروع الآن متاح على:
    echo %REPO_URL%
    echo.
)

pause

