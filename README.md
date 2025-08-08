"# certificate_systems" 


# 🏫 Internship Certificate Generation & Management System

This is a robust, full-featured **Django-based web application** designed to **generate, manage, and verify internship certificates** for students. The system supports **role-based access** (Admin, Coordinator, Student), **customizable certificate templates**, **secure login**, **AJAX-based forms**, and **PDF certificate generation** using **WeasyPrint**.

> ✅ Built for educational institutions, training centers, and internship providers who need a reliable, secure, and modern certificate management system.

---

## 🚀 Key Features

### 🔐 **Role-Based Access**
- **Admin**: Full control over users, templates, and all certificates.
- **Coordinator**: Can generate certificates for students.
- **Student**: Can log in to view and download their issued certificates.

### 🧾 **Certificate Management**
- Manual certificate generation through a form
- Bulk certificate upload via CSV (both offer and completion)
- Unique **Certificate Number** and **Credential ID** per certificate
- QR code support for real-time verification

### 🎨 **Custom Template Editor (Admin Only)**
- Rich text editor (TinyMCE/CKEditor)
- Upload background images
- Drag-and-drop or button-based insertion of placeholders (e.g., `{{ student_name }}`)
- Supports fonts, styles, positioning, and live preview

### 📤 **PDF Generation**
- Automatically generates downloadable **WeasyPrint-based PDFs**
- Clean formatting with background images, dynamic fields, and signature placement
- Customizable templates per certificate type

### 📊 **Dashboards**
- **Admin Dashboard**
  - Search filters: student name, domain, certificate type
  - Pagination, previews, downloads, and deletions
  - Manage coordinators, students, and admin users
- **Coordinator Dashboard**
  - Certificate creation interface
  - Real-time updates
- **Student Dashboard**
  - View/download issued certificates securely

### 📬 **Contact Form**
- Frontend contact form on the home page
- Sends email to admin and stores submission in database

### ⚙️ **AJAX-Based Forms**
- Admin can create new admins, coordinators, and students via AJAX forms
- Smooth submission with validation, success messages, and automatic clearing

### 🛡️ **Security & Non-Functional Features**
- Session timeout (e.g., 30 minutes)
- HTTPOnly and Secure cookie flags
- CSRF protection enabled
- Prevents back-navigation after logout
- Optional prevention of simultaneous logins

---

## 📁 Project Structure

```bash
├── accounts/                  # App for user roles, certificates, and dashboard views
│   ├── templates/admin/       # Admin certificate template editor
│   ├── urls.py                
│   ├── models.py
│   ├── views.py               
   └── ...

├── certificate_systems/       # Main project directory 
│   ├── settings.py/      
│   ├── urls.py                              
   └── ...

├── core/                      # App for public pages like Home, About, Contact
│   ├── templates/       
│   ├── templates/login/       # Login pages, Dashboards and HTML templates for Certificate generation
   └── ...

├── media/                     # stores generated certificates and QR codes
├── static/                    # Global css file, Default signatures and backgrounds
├── requirements.txt           # Python package dependencies
├── README.md                  # Project documentation
├── manage.py                  # Django project entry point
└── ...
```

---

## ⚙️ Installation & Setup Guide

### 🔧 Prerequisites
- Python 3.9+
- PostgreSQL (or SQLite for development)
- Virtual environment tool (recommended: `venv`)
- Git

### 🛠️ Steps

```bash
# 1. Clone the repository
git clone https://github.com/Pinesphere-Solutions-11/certificate_systems.git
cd certificate-systems

# 2. Activate the virtual environment
# For Windows:
venv\Scripts\activate
# For macOS/Linux:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run migrations
python manage.py migrate

# 5. (Optional) Create a superuser
python manage.py createsuperuser

# 6. Run the development server
python manage.py runserver
```

🔗 Open your browser and go to:
```
http://127.0.0.1:8000/accounts/login/admin/
```

---

## 🔑 Default URLs

| Role         | Login URL                              |
|--------------|----------------------------------------|
| Admin        | `/accounts/login/admin/`               |
| Coordinator  | `/accounts/login/coordinator/`         |
| Student      | `/accounts/login/student/`             |
| Contact Page | `/contact/`                            |
| Certificate  | `/accounts/certificate/<type>/create/` |

---

## 🧾 Certificate Types Supported

- **Internship Offer Letter**
- **Internship Completion Certificate**

Each certificate includes:
- Auto-incremented certificate number (e.g., PS001, PS002)
- Issue date, start & end dates
- Student details
- QR code for authenticity check
- Admin signature and logo (from uploaded media)
- Background image and template styling (from template editor)

---

## 📦 Requirements.txt

```txt
Django>=4.0
WeasyPrint>=60.0
qrcode
psycopg2-binary
reportlab
pytz
```

---

## 🛡️ Security & Best Practices

- ✅ CSRF protection enabled on all forms
- ✅ Session cookies are marked as `HTTPOnly` and `Secure`
- ✅ Prevent back-navigation post logout (cache control headers)
- ✅ Optional: Prevent multiple simultaneous logins (session validation)
- ✅ Separate templates for each certificate type
- ✅ Input validation and exception handling implemented

---

## 📧 Email Setup (for contact form notifications)

In `settings.py`, configure:

```python
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.yourprovider.com'
EMAIL_PORT = 587
EMAIL_HOST_USER = 'your-email@example.com'
EMAIL_HOST_PASSWORD = 'your-password'
EMAIL_USE_TLS = True
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER
```

---

<!-- ## 📸 Screenshots (Optional)

> Add screenshots of:
> - Admin dashboard
> - Certificate template editor
> - Sample generated certificate PDF
> - Student dashboard -->

---

## 📜 License

This project is intended for academic and organizational use.  
For customization, deployment support, or licensing for commercial use, **please contact the project maintainer**.

---

## 🤝 Contact

For questions, bugs, or suggestions:

- 📧 Email: [your-email@example.com]
- 🌐 Website: [https://your-portfolio-site.com]
