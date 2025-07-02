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
from django.conf import settings
from datetime import datetime
from .forms import LoginForm, CoordinatorForm, StudentForm, AdminUserForm
from .models import Certificate, Coordinator, Student, AdminUser, User
from datetime import datetime
from django.http import JsonResponse
from .models import Certificate
from django.core.paginator import Paginator
from django.db.models import Q

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
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib import messages
from django.core.paginator import Paginator
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Q
from .models import Certificate, Coordinator, Student, AdminUser
from .forms import CoordinatorForm, StudentForm, AdminUserForm
from django.contrib.auth.decorators import login_required, user_passes_test


@login_required
@user_passes_test(is_admin)
def admin_dashboard(request):
    certificates = Certificate.objects.all().order_by('-created_at')

    # === Filter Parameters from GET ===
    cert_type = request.GET.get('type', '')
    student_name = request.GET.get('student_name', '')
    course_name = request.GET.get('course_name', '')

    if cert_type:
        certificates = certificates.filter(certificate_type__icontains=cert_type)
    if student_name:
        certificates = certificates.filter(student_name__icontains=student_name)
    if course_name:
        certificates = certificates.filter(course_name__icontains=course_name)

    paginator = Paginator(certificates, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    if request.method == 'POST':
        form_type = request.POST.get('form_type')

        if form_type == 'coordinator':
            form = CoordinatorForm(request.POST)
            if form.is_valid():
                form.save()
                if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                    return JsonResponse({'status': 'success', 'message': 'Coordinator added successfully!'})
                messages.success(request, 'Coordinator added successfully!')
                return redirect('admin_dashboard')
            else:
                return JsonResponse({'status': 'error', 'message': form.errors.as_json()}, status=400)

        elif form_type == 'student':
            form = StudentForm(request.POST)
            if form.is_valid():
                form.save()
                if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                    return JsonResponse({'status': 'success', 'message': 'Student added successfully!'})
                messages.success(request, 'Student added successfully!')
                return redirect('admin_dashboard')
            else:
                return JsonResponse({'status': 'error', 'message': form.errors.as_json()}, status=400)

        elif form_type == 'admin':
            form = AdminUserForm(request.POST)
            if form.is_valid():
                from django.contrib.auth.hashers import make_password

                admin = form.save(commit=False)
                admin.password = make_password(form.cleaned_data['password'])  # ✅ Hashed
                admin.save()
                return JsonResponse({'status': 'success', 'message': 'Admin added successfully!'})
                messages.success(request, 'Admin added successfully!')
                return redirect('admin_dashboard')
            else:
                return JsonResponse({'status': 'error', 'message': form.errors.as_json()}, status=400)

    context = {
        'certificates': page_obj,
        'page_obj': page_obj,
        'cert_type': cert_type,
        'student_name': student_name,
        'course_name': course_name,
        'coordinator_count': Coordinator.objects.count(),
        'student_count': Student.objects.count(),
        'total_certificates': Certificate.objects.count(),
    }
    return render(request, 'login/admin-dashboard.html', context)


# =========================
# 🧑‍🏫 COORDINATOR DASHBOARD
# =========================

from django.core.paginator import Paginator
from django.db.models import Q
from django.shortcuts import render
from .models import Certificate
@login_required
@user_passes_test(is_coordinator)
def coordinator_dashboard(request):
    certificates = Certificate.objects.filter(created_by=request.user).order_by('-created_at')

    # --- Get filters from query params ---
    cert_type = request.GET.get('type')
    student_name = request.GET.get('student_name')
    course_name = request.GET.get('course_name')

    # --- Apply filters ---
    if cert_type:
        certificates = certificates.filter(certificate_type=cert_type)
    if student_name:
        certificates = certificates.filter(student_name__icontains=student_name)
    if course_name:
        certificates = certificates.filter(course_name__icontains=course_name)

    # --- Pagination ---
    paginator = Paginator(certificates, 10)  # Show 10 certificates per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'certificates': page_obj,
        'page_obj': page_obj,
        'cert_type': cert_type or '',
        'student_name': student_name or '',
        'course_name': course_name or '',
    }
    return render(request, 'login/coordinator-dashboard.html', context)


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
    import os
    from weasyprint import HTML
    from django.template.loader import render_to_string
    import tempfile

    static_path = os.path.join(settings.BASE_DIR, 'static').replace('\\', '/')
    base_url = f'file:///{static_path}'

    html_string = render_to_string(template_name, {
        'certificate': certificate,
        'base_url': base_url
    })

    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    tmp_file.close()

    HTML(string=html_string, base_url=base_url).write_pdf(tmp_file.name)

    with open(tmp_file.name, 'rb') as pdf_file:
        certificate.generated_pdf.save(
            f"{certificate.student_name}_{certificate.certificate_type}.pdf",
            File(pdf_file)
        )

    os.remove(tmp_file.name)

# COORDINATOR ADD STUDENT FORM #
from django.http import JsonResponse
from .models import Student

def add_student(request):
    if request.method == 'POST':
        full_name = request.POST.get('student_name')
        email = request.POST.get('student_email')
        student_id = request.POST.get('student_id')
        department = request.POST.get('student_department')

        if not all([full_name, email, student_id, department]):
            return JsonResponse({'status': 'error', 'message': 'All fields are required'})

        Student.objects.create(
            full_name=full_name,
            email=email,
            student_id=student_id,
            department=department
        )

        return JsonResponse({'status': 'success', 'message': 'Student added successfully!'})

    return JsonResponse({'status': 'error', 'message': 'Invalid request'})

# Offer Letter Generation #
from datetime import datetime, date

@login_required
@user_passes_test(is_coordinator)
def create_offer_letter(request):
    if request.method == 'POST':
        data = request.POST
        signature_file = request.FILES.get('offerSignature')

        # Convert dates
        try:
            start_date = datetime.strptime(data.get('offerStartDate'), '%Y-%m-%d').date()
            end_date = datetime.strptime(data.get('offerEndDate'), '%Y-%m-%d').date()
            issue_date = datetime.strptime(data.get('offerIssueDate'), '%Y-%m-%d').date()
        except Exception:
            return JsonResponse({'status': 'error', 'message': 'Invalid date format'}, status=400)

        # Create certificate
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
            start_date=start_date,
            end_date=end_date,
            completion_date=issue_date,
            issue_date=issue_date,  # ✅ CURRENT DATE FOR ISSUE DATE
            director_name=data.get('offerDirector'),
            signature=signature_file,
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
            'date': cert.issue_date.strftime('%Y-%m-%d')
        })

    return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)

# Completion Letter Generation #
from datetime import datetime

@login_required
@user_passes_test(is_coordinator)
def create_completion_certificate(request):
    if request.method == 'POST':
        data = request.POST
        signature_file = request.FILES.get('completionSignature')

        try:
            start_date = datetime.strptime(data.get('completionStartDate'), '%Y-%m-%d').date()
            end_date = datetime.strptime(data.get('completionEndDate'), '%Y-%m-%d').date()
            issue_date = datetime.strptime(data.get('completionIssueDate'), '%Y-%m-%d').date()
        except (ValueError, TypeError):
            return JsonResponse({'status': 'error', 'message': 'Invalid or missing date(s)'}, status=400)

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
            start_date=start_date,
            end_date=end_date,
            completion_date=issue_date,  # ⬅️ Assign to model field
            issue_date=issue_date,       # ⬅️ IMPORTANT: assign it properly
            director_name=data.get('completionDirector'),
            signature=signature_file,
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
            'date': cert.issue_date.strftime('%Y-%m-%d')
        })

    return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)

