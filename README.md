# certificate_systems

# 🏫 Internship Certificate Generation & Management System

This is a robust, full-featured **Django-based web application** designed to **generate, manage, and verify internship certificates** for students.  
It supports **role-based access** (Admin, Coordinator, Student), **customizable certificate templates**, **secure login**, **AJAX-based forms**, and **PDF certificate generation** using **WeasyPrint**.

> ✅ Built for educational institutions, training centers, and internship providers who need a reliable, secure, and modern certificate management system.

---

## 🚀 Key Features

### 🔐 **Role-Based Access**
- **Admin**: Full control over users, templates, queries, and certificates.
- **Coordinator**: Can generate certificates and manage student queries.
- **Student**: Can log in, view, download certificates, and raise queries.

### 🧾 **Certificate Management**
- Manual certificate generation (Offer + Completion)
- Bulk upload via CSV/Excel
- Unique **Certificate Number** and **Credential ID**
- QR code for authenticity verification
- PDF generation with **WeasyPrint**

### 📤 **PDF Generation**
- Dynamic placeholders (`student_name`, `student_id`, `course_name`, etc.)
- Background image and digital signatures
- Auto-generated downloadable PDFs

### 📊 **Dashboards**
- **Admin Dashboard**
  - Manage coordinators, students, and admin users
  - Preview, download, and delete certificates
  - Select and apply templates
  - Manage student queries (view, resolve, delete)
- **Coordinator Dashboard**
  - Create certificates (manual & bulk)
  - Apply filters and pagination
  - View assigned certificates
  - Manage student queries
- **Student Dashboard**
  - Login with student ID + name
  - View/download issued certificates
  - Raise queries to admin/coordinators

### 📬 **Contact Form**
- Public contact form with database + email notification
- Async email sending with threading

### 🛡️ **Security & Non-Functional Features**
- Session timeout (30 mins)
- CSRF protection enabled
- HTTPOnly & Secure cookie flags
- Prevents back navigation after logout
- Optional prevention of simultaneous logins

---

## 📁 Project Structure

```bash
├── accounts/                  # Users, certificates, dashboards
│   ├── templates/admin/       # Template editor
│   ├── urls.py                
│   ├── models.py
│   ├── utils.py               # Helper Function
│   ├── views.py               
│   └── ...
├── certificate_systems/       # Main project directory 
│   ├── settings.py      
│   ├── urls.py                              
│   └── ...
├── core/                      # Public pages (Home, About, Contact)
│   ├── templates/       
│   ├── templates/login/       # Login pages & dashboards
│   └── ...
├── media/                     # Certificates, QR codes, uploads
├── static/                    # CSS, default assets
├── requirements.txt           # Dependencies
├── README.md                  # Documentation
├── manage.py                  # Django entry point
└── ...
```

---

## ⚙️ Installation & Setup Guide

### 🔧 Prerequisites
- Python 3.9+
- PostgreSQL
- Virtual environment tool (`venv` recommended)
- Git

### 🛠️ Steps

```bash
# 1. Clone the repository
git clone https://github.com/Pinesphere-Solutions-11/certificate_systems.git


# 2. Create virtual environment
python -m venv venv

cd certificate_systems

# 3. Activate environment
# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Run migrations
python manage.py makemigrations
python manage.py migrate

# 6. (Optional) Create a superuser
python manage.py createsuperuser

# 7. Run server
python manage.py runserver
```

Open: [http://127.0.0.1:8000/accounts/login/admin/](http://127.0.0.1:8000/accounts/login/admin/)

---

## 🔑 Default URLs

| Role         | URL                                   |
|--------------|---------------------------------------|
| Admin        | `/accounts/login/admin/`              |
| Coordinator  | `/accounts/login/coordinator/`        |
| Student      | `/accounts/login/student/`            |
| Contact      | `/contact/`                           |
| Certificate  | `/accounts/certificate/<type>/create/`|
| Verification | `/verify/?id=<credential_id>`         |

---

## 🧾 Certificate Types
- **Internship Offer Letter**
- **Internship Completion Certificate**

Each includes:
- Auto-incremented number (`PS001` etc.)
- Credential ID (16-digit unique)
- Issue, start, and end dates
- QR code for verification
- Student details + signature

---

## 📦 Requirements

```txt
Django>=4.0
WeasyPrint>=60.0
qrcode
psycopg2-binary
reportlab
pytz
pandas
python-dateutil
```

---

## 🛡️ Security & Best Practices
- ✅ CSRF protection on forms
- ✅ Secure, HTTPOnly cookies
- ✅ Cache-control on logout
- ✅ Session timeout enabled
- ✅ Role-based access enforced
- ✅ Error handling + JSON responses

---

## 📧 Email Setup
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

## 📜 License
Academic and organizational use only.  
For commercial support, contact the maintainer.

---

## 🤝 Contact
- 📧 Email: your-email@example.com
- 🌐 Website: https://your-portfolio-site.com
