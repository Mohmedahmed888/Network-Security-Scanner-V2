# تعليمات رفع المشروع على GitHub

## الخطوات:

### 1. إنشاء Repository جديد على GitHub

1. اذهب إلى [GitHub.com](https://github.com)
2. اضغط على **"+"** في الأعلى → **"New repository"**
3. اكتب اسم المشروع (مثلاً: `network-security-scanner`)
4. اختر **Public** أو **Private**
5. **لا** تضع علامة على "Initialize with README"
6. اضغط **"Create repository"**

### 2. رفع المشروع من Command Prompt

افتح Command Prompt في مجلد المشروع واكتب:

```bash
# تهيئة Git (إذا لم تكن مستخدم Git من قبل)
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"

# تهيئة المشروع
git init

# إضافة جميع الملفات
git add .

# عمل Commit
git commit -m "Initial commit: Network Security Scanner"

# إضافة Remote Repository (استبدل YOUR_USERNAME و REPO_NAME)
git remote add origin https://github.com/YOUR_USERNAME/REPO_NAME.git

# رفع المشروع
git branch -M main
git push -u origin main
```

### 3. أو استخدم GitHub Desktop

1. حمّل [GitHub Desktop](https://desktop.github.com/)
2. افتح GitHub Desktop
3. اضغط **File** → **Add Local Repository**
4. اختر مجلد المشروع
5. اضغط **Publish repository**
6. اختر اسم المشروع واكتب وصف
7. اضغط **Publish Repository**

## ملاحظات مهمة:

- ✅ ملف `.gitignore` موجود - سيتم تجاهل الملفات غير الضرورية
- ✅ `README.md` جاهز - يحتوي على وصف المشروع
- ⚠️ لا ترفع ملفات `.exe` الكبيرة (موجودة في .gitignore)
- ⚠️ لا ترفع `__pycache__` أو `build/` أو `dist/`

## بعد الرفع:

1. اذهب إلى صفحة المشروع على GitHub
2. اضغط **Settings** → **Pages** (اختياري - لإنشاء موقع)
3. شارك الرابط مع الآخرين!

