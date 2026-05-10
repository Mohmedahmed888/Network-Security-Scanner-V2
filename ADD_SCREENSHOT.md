# كيفية إضافة الصورة على GitHub

## الخطوات:

### 1. أخذ Screenshot:
- اضغط `Windows + Shift + S` لأخذ screenshot
- أو استخدم أي برنامج screenshot
- احفظ الصورة بصيغة PNG أو JPG

### 2. حفظ الصورة:
- انسخ الصورة إلى مجلد `screenshots`
- اسم الصورة: `main-window.png` (أو أي اسم تريده)

### 3. رفع الصورة على GitHub:

**الطريقة 1: من GitHub Website**
1. اذهب إلى: https://github.com/Mohmedahmed888/network-security-scanner
2. اضغط على مجلد `screenshots`
3. اضغط **"Add file"** → **"Upload files"**
4. اسحب الصورة أو اضغط **"choose your files"**
5. اضغط **"Commit changes"**

**الطريقة 2: من Command Prompt**
```bash
# انسخ الصورة إلى مجلد screenshots
# ثم:
git add screenshots/main-window.png
git commit -m "Add application screenshot"
git push
```

**الطريقة 3: استخدام GitHub Desktop**
1. افتح GitHub Desktop
2. اسحب الصورة إلى مجلد screenshots
3. اضغط Commit و Push

## ملاحظات:
- استخدم أسماء واضحة للصور (مثل: `main-window.png`, `scan-results.png`)
- حجم الصورة: حاول أن تكون أقل من 1MB
- الصيغة المفضلة: PNG للشاشات، JPG للصور

