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

@login_required
@user_passes_test(is_admin)


def admin_dashboard(request):
    certificates = Certificate.objects.all().order_by('-created_at')

    # === Filter Parameters from GET ===
    query = request.GET.get('query', '')
    cert_type = request.GET.get('type', '')
    student_id = request.GET.get('student_id', '')
    domain = request.GET.get('course_name', '')

    # === Filtering Certificates Based on Query Params ===
    if query or cert_type or student_id or domain:
        certificates = certificates.filter(
            Q(student_name__icontains=query) &
            Q(certificate_type__icontains=cert_type) &
            Q(student_id__icontains=student_id) &
            Q(course_name__icontains=domain)
        )

    # === Pagination ===
    paginator = Paginator(certificates, 10)  # Show 10 certificates per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # === Form Submission Handling (POST) ===
    if request.method == 'POST':
        form_type = request.POST.get('form_type')

        if form_type == 'coordinator':
            form = CoordinatorForm(request.POST)
            if form.is_valid():
                form.save()
                messages.success(request, 'Coordinator added successfully!')
                return redirect('admin_dashboard')
            else:
                print("CoordinatorForm errors:", form.errors)

        elif form_type == 'student':
            form = StudentForm(request.POST)
            if form.is_valid():
                form.save()
                messages.success(request, 'Student added successfully!')
                return redirect('admin_dashboard')
            else:
                print("StudentForm errors:", form.errors)

        elif form_type == 'admin':
            admin_form = AdminUserForm(request.POST)
            if admin_form.is_valid():
                admin = admin_form.save(commit=False)
                admin.set_password(admin_form.cleaned_data['password'])  # Hash the password
                admin.save()
                messages.success(request, 'Admin added successfully!')
                return redirect('admin_dashboard')
            else:
                print("AdminUserForm errors:", admin_form.errors)

    # === Context for Template ===
    context = {
        'coordinator_count': Coordinator.objects.count(),
        'student_count': Student.objects.count(),
        'total_certificates': Certificate.objects.count(),
        'certificates': page_obj,
        'page_obj': page_obj,
        'query': query,
        'cert_type': cert_type,
        'student_id_filter': student_id,
        'domain_filter': domain,
    }

    return render(request, 'login/admin-dashboard.html', context)


# =========================
# 🧑‍🏫 COORDINATOR DASHBOARD
# =========================
from django.core.paginator import Paginator
from django.db.models import Q
@login_required
@user_passes_test(is_coordinator)


def coordinator_dashboard(request):
    certificates = Certificate.objects.filter(created_by=request.user).order_by('-created_at')

    # --- Filtering ---
    cert_type = request.GET.get('type')
    student_id = request.GET.get('student_id')
    domain = request.GET.get('domain')

    if cert_type:
        certificates = certificates.filter(certificate_type=cert_type)

    if student_id:
        certificates = certificates.filter(student_id__icontains=student_id)

    if domain:
        certificates = certificates.filter(course_name__icontains=domain)

    # --- Pagination ---
    paginator = Paginator(certificates, 10)  # Show 10 per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'certificates': page_obj,
        'page_obj': page_obj,
        'cert_type': cert_type or '',
        'student_id': student_id or '',
        'domain': domain or '',
    }
    return render(request, 'login/coordinator-dashboard.html', context)



# =========================
# 👨‍🎓 STUDENT DASHBOARD
# =========================


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
            f"{certificate.student_id}_{certificate.certificate_type}.pdf",
            File(pdf_file)
        )

    os.remove(tmp_file.name)

# COORDINATOR ADD STUDENT FORM #
def add_student(request):
    if request.method == 'POST':
        name = request.POST.get('student_name')
        email = request.POST.get('student_email')
        student_id = request.POST.get('student_id')
        department = request.POST.get('student_department')  # ← use department now

        if not all([name, email, student_id, department]):
            return JsonResponse({'status': 'error', 'message': 'All fields are required'}, status=400)

        if Student.objects.filter(student_id=student_id).exists():
            return JsonResponse({'status': 'error', 'message': 'Student already exists'}, status=400)

        Student.objects.create(
            full_name=name,
            email=email,
            student_id=student_id,
            department=department  # ← updated here too
        )

        return JsonResponse({'status': 'success', 'message': 'Student added successfully!'})

    return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)


@login_required
@user_passes_test(is_coordinator)
def create_offer_letter(request):
    if request.method == 'POST':
        data = request.POST
        signature_file = request.FILES.get('offerSignature')
        start_date = datetime.strptime(data.get('offerStartDate'), '%Y-%m-%d').date()
        end_date = datetime.strptime(data.get('offerEndDate'), '%Y-%m-%d').date()
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
            signature=signature_file,
            start_date = start_date,
            end_date = end_date,
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

        # Get and validate dates
        start_date_str = data.get('completionStartDate')
        end_date_str = data.get('completionEndDate')
        completion_date_str = data.get('completionDate')

        if not start_date_str or not end_date_str or not completion_date_str:
            return JsonResponse({'status': 'error', 'message': 'All dates are required'}, status=400)

        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
            completion_date = datetime.strptime(completion_date_str, '%Y-%m-%d').date()
        except ValueError:
            return JsonResponse({'status': 'error', 'message': 'Invalid date format (must be YYYY-MM-DD)'}, status=400)

        # Create certificate
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
            completion_date=completion_date,
            director_name=data.get('completionDirector'),
            start_date=start_date,
            end_date=end_date,
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

