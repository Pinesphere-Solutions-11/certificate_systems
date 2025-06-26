from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.urls import reverse
from django.http import JsonResponse, FileResponse
from django.template.loader import render_to_string
from weasyprint import HTML
from django.core.files.base import File
import tempfile
from datetime import datetime
from .forms import LoginForm, CoordinatorForm, StudentForm, AdminUserForm
from .models import Certificate, Coordinator, Student, AdminUser, User

# =========================
# 🔐 AUTH SYSTEM
# =========================

def login_view(request, role):
    logout(request)
    template_map = {
        'admin': 'login-admin.html',
        'coordinator': 'login-coordinator.html',
        'student': 'login-student.html',
    }

    if role not in template_map:
        return redirect('login', role='student')

    form = LoginForm(data=request.POST or None)

    if request.method == 'POST':
        if form.is_valid():
            user = form.get_user()
            if user.role != role:
                messages.error(request, "You are not authorized to log in as this role.")
            else:
                login(request, user)
                return redirect('dashboard_redirect')
        else:
            messages.error(request, "Invalid credentials. Please try again.")

    return render(request, f'login/{template_map[role]}', {'form': form})


def logout_view(request):
    logout(request)
    return redirect('login', role='student')


@login_required
def dashboard_redirect(request):
    if request.user.role == 'admin':
        return redirect('admin_dashboard')
    elif request.user.role == 'coordinator':
        return redirect('coordinator_dashboard')
    else:
        return redirect('student_dashboard')

# =========================
# 👥 ROLE CHECKS
# =========================

def is_admin(user):
    return user.is_authenticated and user.role == 'admin'

def is_coordinator(user):
    return user.is_authenticated and user.role == 'coordinator'

def is_student(user):
    return user.is_authenticated and user.role == 'student'

# =========================
# 📊 ADMIN DASHBOARD
# =========================

@login_required
@user_passes_test(is_admin)
def admin_dashboard(request):
    if request.method == 'POST':
        form_type = request.POST.get('form_type')

        if form_type == 'coordinator':
            form = CoordinatorForm(request.POST)
            if form.is_valid():
                form.save()
                messages.success(request, 'Coordinator added successfully!')
                return redirect('admin_dashboard')

        elif form_type == 'student':
            form = StudentForm(request.POST)
            if form.is_valid():
                form.save()
                messages.success(request, 'Student added successfully!')
                return redirect('admin_dashboard')

        elif form_type == 'admin':
            form = AdminUserForm(request.POST)
            if form.is_valid():
                form.save()
                messages.success(request, 'Admin added successfully!')
                return redirect('admin_dashboard')

    context = {
        'coordinator_count': Coordinator.objects.count(),
        'student_count': Student.objects.count(),
        'total_certificates': Certificate.objects.count(),
    }
    return render(request, 'login/admin-dashboard.html', context)

# =========================
# 🧑‍🏫 COORDINATOR DASHBOARD
# =========================

@login_required
@user_passes_test(is_coordinator)
def coordinator_dashboard(request):
    return render(request, 'login/coordinator-dashboard.html')


# =========================
# 👨‍🎓 STUDENT DASHBOARD
# =========================

@login_required
@user_passes_test(is_student)
def student_dashboard(request):
    certs = Certificate.objects.filter(student_id=request.user.username)
    return render(request, 'login/student-dashboard.html', {'certificates': certs})

@login_required
@user_passes_test(is_student)
def download_certificate(request, cert_id):
    cert = get_object_or_404(Certificate, id=cert_id, student_id=request.user.username)
    return FileResponse(cert.generated_pdf, as_attachment=True)


# =========================
# 📝 CERTIFICATE CREATION VIEWS
# =========================

import os
import tempfile
from weasyprint import HTML
from django.core.files.base import File

def generate_certificate_pdf(certificate, template_name):
    html_string = render_to_string(template_name, {'certificate': certificate})

    # Create a named temp file and close it immediately (for Windows compatibility)
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    tmp_file.close()

    # WeasyPrint writes to it
    HTML(string=html_string).write_pdf(tmp_file.name)

    # Save to Django FileField
    with open(tmp_file.name, 'rb') as pdf_file:
        certificate.generated_pdf.save(
            f"{certificate.student_id}_{certificate.certificate_type}.pdf",
            File(pdf_file)
        )

    # Clean up temp file
    os.unlink(tmp_file.name)


from datetime import datetime

@login_required
@user_passes_test(is_coordinator)
def create_offer_letter(request):
    if request.method == 'POST':
        data = request.POST

        cert = Certificate(
            certificate_type='offer',
            title=data.get('offerTitle'),
            student_name=data.get('offerStudentName'),
            student_id=data.get('offerRegisterNumber'),
            department=data.get('offerDepartment'),
            college=data.get('offerCollege'),
            location=data.get('offerLocation'),
            course_name=data.get('offerCourseName'),
            duration=data.get('offerDuration'),
            completion_date=datetime.strptime(data.get('offerEndDate'), '%Y-%m-%d').date(),
            director_name=data.get('offerDirector'),
            created_by=request.user,
        )

        cert.save()
        generate_certificate_pdf(cert, 'login/internship_offer.html')

        return JsonResponse({
            'status': 'success',
            'message': 'Offer Letter created successfully!',
            'certificate_number': cert.certificate_number,
            'student': cert.student_name,
            'course': cert.course_name,
            'date': cert.completion_date.strftime('%Y-%m-%d')
        })

    return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)


@login_required
@user_passes_test(is_coordinator)
def create_completion_certificate(request):
    if request.method == 'POST':
        data = request.POST

        cert = Certificate(
            certificate_type='completion',
            title=data.get('completionTitle'),
            student_name=data.get('completionStudentName'),
            student_id=data.get('completionRegisterNumber'),
            department=data.get('completionDepartment'),
            college=data.get('completionCollege'),
            location=data.get('completionLocation'),
            course_name=data.get('completionCourseName'),
            duration=data.get('completionDuration'),
            completion_date=datetime.strptime(data.get('completionDate'), '%Y-%m-%d').date(),
            director_name=data.get('completionDirector'),
            created_by=request.user,
        )

        cert.save()
        generate_certificate_pdf(cert, 'login/internship_completion.html')

        return JsonResponse({
            'status': 'success',
            'message': 'Completion Certificate created successfully!',
            'certificate_number': cert.certificate_number,
            'student': cert.student_name,
            'course': cert.course_name,
            'date': cert.completion_date.strftime('%Y-%m-%d')
        })

    return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)
