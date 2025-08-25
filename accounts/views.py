import csv
from io import BytesIO
import json
from string import Template
from uuid import uuid4
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.http import Http404, HttpResponse, HttpResponseBadRequest, JsonResponse, FileResponse
from weasyprint import HTML
from django.core.files.base import File
import tempfile
from django.conf import settings
from datetime import datetime
from .forms import CoordinatorForm, StudentForm, AdminUserForm
from .models import ContactMessage, Certificate, Coordinator, Student, User
from datetime import datetime
from django.http import JsonResponse
from .models import Certificate
from django.core.paginator import Paginator
from django.db.models import Q
from django.core.mail import send_mail
from django.conf import settings
from django.core.mail import send_mail
import threading
from .models import User
from .models import Student
from .models import CertificateTemplate
from django.core.files.storage import default_storage
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.cache import cache_control
from django.views.decorators.cache import cache_control, never_cache

# Function for admin only login
def is_admin(user):
    return user.is_authenticated and user.role == 'admin'

 
@login_required
@user_passes_test(is_admin)
def template_editor(request):
    return render(request, 'admin/certificate_editor.html')

@login_required
@user_passes_test(is_admin)
def template_editor(request):
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return render(request, "admin/certificate.html")
    return render(request, "admin/certificate.html") 

@login_required
@user_passes_test(is_admin)
@csrf_exempt
def save_certificate_template(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            certificate_type = data.get("certificate_type")
            html_content = data.get("html_content")

            if not certificate_type or not html_content:
                return JsonResponse({"status": "error", "message": "Missing template data"}, status=400)

            CertificateTemplate.objects.update_or_create(
                template_type=certificate_type,
                defaults={"html_content": html_content}
            )

            return JsonResponse({"status": "success", "message": "Template saved successfully!"})

        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)}, status=500)

    return JsonResponse({"status": "error", "message": "Invalid request method"}, status=405)

@login_required
@user_passes_test(is_admin)
def save_template(request):
    if request.method == 'POST':
        try:
            name = request.POST.get('template_name')
            certificate_type = request.POST.get('certificate_type')
            html_content = request.POST.get('html_content', '')
            css_content = request.POST.get('css_content', '')
            background_image = request.FILES.get('background_image')

            #  Replace placeholders with real Django template tags
            PLACEHOLDER_MAP = {
                "[[student_name]]": "{{ certificate.student_name }}",
                "[[student_id]]": "{{ certificate.student_id }}",
                "[[course_name]]": "{{ certificate.course_name }}",
                "[[start_date]]": "{{ certificate.start_date|date:'d M Y' }}",
                "[[end_date]]": "{{ certificate.end_date|date:'d M Y' }}",
                "[[director_name]]": "{{ certificate.director_name }}",
                "[[signature]]": "{% if certificate.signature %}<img src='{{ base_media_url }}/{{ certificate.signature.name }}' class='signature-img'>{% endif %}",
                "[[qr_code]]": "{% if certificate.qr_code_path %}<img src='{{ base_media_url }}/{{ certificate.qr_code_path.name }}' class='qr-img'>{% endif %}",
                "[[credential_id]]": "{{ certificate.credential_id }}",
                "[[issue_date]]": "{{ certificate.issue_date|date:'d M Y' }}",
            }
            for placeholder, tag in PLACEHOLDER_MAP.items():
                html_content = html_content.replace(placeholder, tag)

            #  Add CSS content if provided
            if css_content:
                html_content = f"<style>{css_content}</style>{html_content}"

            #  Add background if uploaded
            if background_image:
                # NOTE: we don’t hardcode file path; instead we rely on template rendering later
                style_block = """
                <style>
                    body {
                        background: url('{{ base_media_url }}/{{ certificate_template.background_image.name }}') no-repeat center center;
                        background-size: cover;
                    }
                </style>
                """
                html_content = style_block + html_content

            #  Save or update template
            template, created = CertificateTemplate.objects.update_or_create(
                template_type=certificate_type,
                defaults={
                    'html_content': html_content,
                    'background_image': background_image if background_image else None,
                }
            )

            return JsonResponse({
                'status': 'success',
                'message': 'Template saved successfully',
                'template_id': template.id
            })

        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})


@login_required
def ping_session(request):
    return HttpResponse("pong")

def create_student_user(name, student_id):
    username = name.strip().lower().replace(" ", "")
    if not User.objects.filter(username=username).exists():
        user = User.objects.create_user(username=username, password=student_id)
        user.save()

def send_email_async(subject, message, from_email, recipient_list):
    threading.Thread(target=send_mail, args=(subject, message, from_email, recipient_list)).start()

def contact_view(request):
    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        email = request.POST.get('email', '').strip()
        subject = request.POST.get('subject', '').strip()
        message = request.POST.get('message', '').strip()

        if name and email and subject and message:
            obj = ContactMessage.objects.create(
                name=name,
                email=email,
                subject=subject,
                message=message
            )
            print("SAVED TO DATABASE:", obj)

            full_message = f"From: {name} <{email}>\n\nMessage: \n\t {message}"
            send_email_async(subject, full_message, settings.EMAIL_HOST_USER, [settings.ADMIN_EMAIL])

            from django.contrib import messages
            messages.success(request, "Your message has been sent!")
            return redirect('contact')

        else:
            print("❌ Validation failed — missing fields")
            from django.contrib import messages
            messages.error(request, "Please fill in all fields.")

    return render(request, 'contact.html')

def login_view(request, role):
    from django.contrib.auth.forms import AuthenticationForm
    from django.contrib.auth import login, logout

    logout(request)
    form = None

    template_map = {
        'admin': 'login-admin.html',
        'coordinator': 'login-coordinator.html',
        'student': 'login-student.html',
    }

    if role not in template_map:
        return redirect('login', role='student')
    

    # ✅ STUDENT LOGIN using Certificate model
    if role == 'student':
        if request.method == 'POST':
            username = request.POST.get('username', '').strip().lower().replace(" ", "")
            password = request.POST.get('password', '').strip()

            # Search in Certificate table
            try:
                certificate = next(
                    cert for cert in Certificate.objects.all()
                    if cert.student_name.strip().lower().replace(" ", "") == username
                    and cert.student_id == password
                )

                # Save student ID in session for dashboard use
                request.session['student_name'] = certificate.student_name
                request.session['student_id'] = certificate.student_id
                return redirect('student_dashboard')

            except StopIteration:
                messages.error(request, "Invalid student name or register number.")
        
        return render(request, f'login/{template_map[role]}')  # no form context needed for student

    # ✅ ADMIN / COORDINATOR login
    else:
        form = AuthenticationForm(data=request.POST or None)

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


@never_cache
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def logout_view(request):
    logout(request)  # Clears Django session & user data
    request.session.flush()  # Extra precaution: remove all session data
    response = redirect('index')  # Redirect to home page
    response.delete_cookie('sessionid')  # Delete session cookie explicitly
    return response


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
from django.db.models import Q
from .models import Certificate, Coordinator, Student, AdminUser
from .forms import  StudentForm, AdminUserForm, CoordinatorForm
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.hashers import make_password
from django.core.paginator import Paginator
from accounts.models import Certificate, Student, Coordinator, AdminUser, User 



@login_required
@user_passes_test(is_admin)
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@never_cache
def admin_dashboard(request):
    
    certificates = Certificate.objects.all().order_by('-created_at')
    
    admins = AdminUser.objects.select_related('user').all()
    coordinators = Coordinator.objects.select_related('user').all()
    # certificates = Certificate.objects.all()
    
    offer_certificates = Certificate.objects.filter(certificate_type='offer')
    completion_certificates = Certificate.objects.filter(certificate_type='completion')
    

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

    # === Handle POST Form Submissions ===
    if request.method == 'POST':
        form_type = request.POST.get('form_type')

        if form_type == 'coordinator':
            full_name = request.POST.get('full_name')
            email = request.POST.get('email')
            designation = request.POST.get('designation')
            employment_id = request.POST.get('employment_id')
            phone = request.POST.get('phone', '')

            if not all([full_name, email, employment_id]):
                return JsonResponse({'status': 'error', 'message': 'All fields except  designation and phone are required.'}, status=400)

            if User.objects.filter(username=email).exists():
                return JsonResponse({'status': 'error', 'message': 'Email already exists.'}, status=400)

            # Create the user account
            user = User.objects.create_user(
                username=email,
                email=email,
                password=employment_id,
                role='coordinator'
            )

            # Create the Coordinator profile
            Coordinator.objects.create(
                user=user,
                full_name=full_name,
                email=email,
                designation=designation,
                employment_id=employment_id,
                phone=phone
            )

            if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                return JsonResponse({'status': 'success', 'message': 'Coordinator added successfully!'})
            
            messages.success(request, 'Coordinator added successfully!')
            return redirect('admin_dashboard')

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
            full_name = request.POST.get('full_name')
            email = request.POST.get('email')
            designation = request.POST.get('designation')
            employment_id = request.POST.get('employment_id')
            phone = request.POST.get('phone', '')

            if not all([full_name, email, employment_id]):
                return JsonResponse({'status': 'error', 'message': 'Full name, email, and employment ID are required.'}, status=400)

            if User.objects.filter(username=email):
                return JsonResponse({'status': 'error', 'message': 'Email already exists.'}, status=400)

            # Create Django User for login
            user = User.objects.create_user(
                username=email,
                email=email,
                password=employment_id,
                role='admin'
            )

            # Create AdminUser profile
            AdminUser.objects.create(
                user=user,
                full_name=full_name,
                email=email,
                designation=designation,
                employment_id=employment_id,
                phone=phone
            )

            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
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
        'admins': admins,
        'coordinators': coordinators,
        'certificates': certificates,
        'offer_certificates': offer_certificates,
        'completion_certificates': completion_certificates,
        'offer_count' : offer_certificates.count(),
        'completion_count' : completion_certificates.count(),
    # 'total_certificates': Certificate.objects.count(),
        'coordinator_count': Coordinator.objects.count(),
        'admin_count' : AdminUser.objects.count(),
    }
    return render(request, 'login/admin-dashboard.html', context)

# =========================
# 🧑‍🏫 COORDINATOR DASHBOARD
# ===========================
from django.shortcuts import render
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.paginator import Paginator
from django.db.models import Q
from .models import Certificate


def is_coordinator(user):
    return user.is_authenticated and getattr(user, 'role', None) == 'coordinator'

@login_required
@user_passes_test(is_coordinator)
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@never_cache
def coordinator_dashboard(request):
    # Initial queryset: all certificates created by the logged-in coordinator
    certificates = Certificate.objects.filter(created_by=request.user).order_by('-created_at')

    # --- Get filters from request GET parameters ---
    cert_type = request.GET.get('type', '').strip()
    student_name = request.GET.get('student_name', '').strip()
    course_name = request.GET.get('course_name', '').strip()

    # --- Apply filters using Q objects ---
    filters = Q()
    if cert_type:
        filters &= Q(certificate_type__iexact=cert_type)
    if student_name:
        filters &= Q(student_name__icontains=student_name)
    if course_name:
        filters &= Q(course_name__icontains=course_name)

    # Apply all filters
    certificates = certificates.filter(filters)

    # --- Paginate results ---
    paginator = Paginator(certificates, 10)  # 10 certificates per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # --- Context for the template ---
    context = {
        'certificates': page_obj,
        'page_obj': page_obj,
        'cert_type': cert_type,
        'student_name': student_name,
        'course_name': course_name,
    }

    return render(request, 'login/coordinator-dashboard.html', context)


# =========================
# 👨‍🎓 STUDENT DASHBOARD
# =========================

@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@never_cache
def student_dashboard(request):
    student_id = request.session.get('student_id')
    student_name = request.session.get('student_name')
    if not student_name:
        return redirect('login', role='student')

    # ✅ Get all certificates where student_id matches
    if (student_name == student_name and student_id == student_id):
        certificates = Certificate.objects.filter(student_name=student_name, student_id=student_id)

    # ✅ Use the name from the first certificate, fallback to "Student"
    student_name = certificates.first().student_name if certificates.exists() else "Student"

    return render(request, 'student-dashboard.html', {
        'student_name': student_name,
        'student_id' : student_id,
        'certificates': certificates
    })


# =========================
# 📝 CERTIFICATE CREATION VIEWS
# =========================

import os
import tempfile
from weasyprint import HTML
from django.core.files.base import File
from .models import CertificateTemplate 
from django.template import Template, Context
from django.template.loader import render_to_string

def generate_certificate_pdf(certificate, default_template_name):
    static_path = os.path.join(settings.BASE_DIR, 'static').replace('\\', '/')
    base_url = f'file:///{static_path}'
    media_path = os.path.join(settings.MEDIA_ROOT).replace('\\', '/')
    base_media_url = f'file:///{media_path}'

    context = {
        'certificate': certificate,
        'base_url': base_url,
        'base_media_url': base_media_url,
    }

    # Always render using the default template
    html_content = render_to_string(default_template_name, context)

    pdf_buffer = BytesIO()
    HTML(string=html_content, base_url=base_url).write_pdf(pdf_buffer)

    certificate.generated_pdf.save(
        f"{certificate.student_name}_{certificate.certificate_type}.pdf",
        File(pdf_buffer),
        save=True
    )

    
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

        return JsonResponse({'status': 'success', 'message': 'Student added successfully!'}, status=200)

    return JsonResponse({'status': 'error', 'message': 'Invalid request'})

# Offer Letter Generation #
from datetime import datetime, date

def is_admin_or_coordinator(user):
    return user.is_authenticated and user.role in ('admin', 'coordinator')

# Admin certificate creation

@login_required
@user_passes_test(is_admin_or_coordinator)
def create_offer_letter(request):
    if request.method == 'POST':
        data = request.POST
        signature_file = request.FILES.get('offerSignature')

        try:
            start_date = datetime.strptime(data.get('offerStartDate'), '%Y-%m-%d').date()
            end_date   = datetime.strptime(data.get('offerEndDate'),   '%Y-%m-%d').date()
            issue_date = datetime.strptime(data.get('offerIssueDate'), '%Y-%m-%d').date()
        except Exception:
            return JsonResponse({'status': 'error', 'message': 'Invalid date format'}, status=400)

        cert = Certificate(
            certificate_type='offer',
            title=data.get('offerTitle'),
            student_name=data.get('offerStudentName'),
            student_id=data.get('offerRegisterNumber'),
            degree=data.get('offerDegree'),
            department=data.get('offerDepartment'),
            college=data.get('offerCollege'),
            location=data.get('offerLocation'),
            course_name=data.get('offerCourseName'),
            duration=data.get('offerDuration'),
            start_date=start_date,
            end_date=end_date,
            completion_date=issue_date,
            issue_date=issue_date,
            director_name=data.get('offerDirector'),
            signature=signature_file,
            created_by=request.user,
        )
        cert.save()

        # ONLY pass the default template name; the function will prefer a DB template if present.
        generate_certificate_pdf(cert, 'login/internship_offer.html')

        return JsonResponse({
            'status': 'success',
            'message': 'Offer Letter created successfully!',
            'certificate_number': cert.certificate_number,
            'credential_id': cert.credential_id,
            'student': cert.student_name,
            'course': cert.course_name,
            'date': cert.issue_date.strftime('%Y-%m-%d'),
            'download_url': cert.generated_pdf.url if cert.generated_pdf else ''
        }, status=200)

    return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)

# Completion Letter Generation #
from datetime import datetime

@login_required
@user_passes_test(is_admin_or_coordinator)
def create_completion_certificate(request):
    if request.method == 'POST':
        data = request.POST
        signature_file = request.FILES.get('completionSignature')

        try:
            start_date = datetime.strptime(data.get('completionStartDate'), '%Y-%m-%d').date()
            end_date   = datetime.strptime(data.get('completionEndDate'),   '%Y-%m-%d').date()
            issue_date = datetime.strptime(data.get('completionIssueDate'), '%Y-%m-%d').date()
        except (ValueError, TypeError):
            return JsonResponse({'status': 'error', 'message': 'Invalid or missing date(s)'}, status=400)

        cert = Certificate(
            certificate_type='completion',
            title=data.get('completionTitle'),
            student_name=data.get('completionStudentName'),
            student_id=data.get('completionRegisterNumber'),
            degree=data.get('completionDegree'),
            department=data.get('completionDepartment'),
            college=data.get('completionCollege'),
            location=data.get('completionLocation'),
            course_name=data.get('completionCourseName'),
            duration=data.get('completionDuration'),
            start_date=start_date,
            end_date=end_date,
            completion_date=issue_date,
            issue_date=issue_date,
            director_name=data.get('completionDirector'),
            signature=signature_file,
            created_by=request.user,
        )
        cert.save()

        # ONLY pass the default template name
        generate_certificate_pdf(cert, 'login/internship_completion.html')

        return JsonResponse({
            'status': 'success',
            'message': 'Completion Certificate created successfully!',
            'certificate_number': cert.certificate_number,
            'credential_id': cert.credential_id,
            'student': cert.student_name,
            'course': cert.course_name,
            'date': cert.issue_date.strftime('%Y-%m-%d'),
            'download_url': cert.generated_pdf.url if cert.generated_pdf else ''
        }, status=200)

    return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)

@csrf_exempt
@login_required
@user_passes_test(is_admin)
def bulk_offer_upload(request):
    if request.method == 'POST' and request.FILES.get('csvFile'):
        csv_file = request.FILES['csvFile']
        decoded = csv_file.read().decode('utf-8').splitlines()
        reader = csv.DictReader(decoded)
        created = []

        for row in reader:
            cert = Certificate.objects.create(
                certificate_type='offer',
                title=row['Title'],
                student_name=row['Student Name'],
                student_id=row['Student ID'],
                department=row['Department'],
                degree=row['Degree'],
                college=row['College'],
                location=row['Location'],
                course_name=row['Course Name'],
                duration=row['Duration'],
                start_date=datetime.strptime(row['Start Date'], '%Y-%m-%d'),
                end_date=datetime.strptime(row['End Date'], '%Y-%m-%d'),
                completion_date=datetime.strptime(row['Issue Date'], '%Y-%m-%d'),
                issue_date=datetime.strptime(row['Issue Date'], '%Y-%m-%d'),
                director_name=row['Director Name'],
                created_by=request.user
            )

            

            generate_certificate_pdf(cert, 'login/internship_offer.html')
            created.append(cert.pk)

        return JsonResponse({'status': 'success', 'created': created}, status=200)
    return JsonResponse({'status': 'error', 'message': 'CSV not found'}, status=400)


@csrf_exempt
@login_required
@user_passes_test(is_admin)
def bulk_completion_upload(request):
    if request.method == 'POST' and request.FILES.get('csvFile'):
        csv_file = request.FILES['csvFile']
        decoded = csv_file.read().decode('utf-8').splitlines()
        reader = csv.DictReader(decoded)
        created = []

        for row in reader:
            cert = Certificate.objects.create(
                certificate_type='completion',
                title=row['Title'],
                student_name=row['Student Name'],
                student_id=row['Student ID'],
                department=row['Department'],
                degree=row['Degree'],
                college=row['College'],
                location=row['Location'],
                course_name=row['Course Name'],
                duration=row['Duration'],
                start_date=datetime.strptime(row['Start Date'], '%Y-%m-%d'),
                end_date=datetime.strptime(row['End Date'], '%Y-%m-%d'),
                completion_date=datetime.strptime(row['Issue Date'], '%Y-%m-%d'),
                issue_date=datetime.strptime(row['Issue Date'], '%Y-%m-%d'),
                director_name=row['Director Name'],
                created_by=request.user
            )

            

            generate_certificate_pdf(cert, 'login/internship_completion.html')
            created.append(cert.pk)

        return JsonResponse({'status': 'success', 'created': created}, status=200)
    return JsonResponse({'status': 'error', 'message': 'CSV not found'}, status=400)


@csrf_exempt
@login_required
@user_passes_test(is_coordinator)
def bulk_offer_upload(request):
    if request.method == 'POST' and request.FILES.get('csvFile'):
        csv_file = request.FILES['csvFile']
        decoded = csv_file.read().decode('utf-8').splitlines()
        reader = csv.DictReader(decoded)
        created = []

        for row in reader:
            cert = Certificate.objects.create(
                certificate_type='offer',
                title=row['Title'],
                student_name=row['Student Name'],
                student_id=row['Student ID'],
                department=row['Department'],
                degree=row['Degree'],
                college=row['College'],
                location=row['Location'],
                course_name=row['Course Name'],
                duration=row['Duration'],
                start_date=datetime.strptime(row['Start Date'], '%Y-%m-%d'),
                end_date=datetime.strptime(row['End Date'], '%Y-%m-%d'),
                completion_date=datetime.strptime(row['Issue Date'], '%Y-%m-%d'),
                issue_date=datetime.strptime(row['Issue Date'], '%Y-%m-%d'),
                director_name=row['Director Name'],
                created_by=request.user
            )

            

            generate_certificate_pdf(cert, 'login/internship_offer.html')
            created.append(cert.pk)

        return JsonResponse({'status': 'success', 'created': created}, status=200)
    return JsonResponse({'status': 'error', 'message': 'CSV not found'}, status=400)


@csrf_exempt
@login_required
@user_passes_test(is_coordinator)
def bulk_completion_upload(request):
    if request.method == 'POST' and request.FILES.get('csvFile'):
        csv_file = request.FILES['csvFile']
        decoded = csv_file.read().decode('utf-8').splitlines()
        reader = csv.DictReader(decoded)
        created = []

        for row in reader:
            cert = Certificate.objects.create(
                certificate_type='completion',
                title=row['Title'],
                student_name=row['Student Name'],
                student_id=row['Student ID'],
                department=row['Department'],
                degree=row['Degree'],
                college=row['College'],
                location=row['Location'],
                course_name=row['Course Name'],
                duration=row['Duration'],
                start_date=datetime.strptime(row['Start Date'], '%Y-%m-%d'),
                end_date=datetime.strptime(row['End Date'], '%Y-%m-%d'),
                completion_date=datetime.strptime(row['Issue Date'], '%Y-%m-%d'),
                issue_date=datetime.strptime(row['Issue Date'], '%Y-%m-%d'),
                director_name=row['Director Name'],
                created_by=request.user
            )

            

            generate_certificate_pdf(cert, 'login/internship_completion.html')
            created.append(cert.pk)

        return JsonResponse({'status': 'success', 'created': created}, status=200)
    return JsonResponse({'status': 'error', 'message': 'CSV not found'}, status=400)



def download_certificate(request, cert_id):
    student_name = request.session.get('student_name')
    student_id = request.session.get('student_id')
    cert = get_object_or_404(Certificate, id=cert_id, student_name=student_name, student_id=student_id)

    if not cert.generated_pdf:
        raise Http404("PDF not available.")

    return FileResponse(cert.generated_pdf.open('rb'), as_attachment=True, filename=f"{cert.student_name}.pdf")

def student_login_view(request):
   if request.method == 'POST':
        username = request.POST.get('username', '').strip().lower()
        password = request.POST.get('password', '').strip()

        try:
            student = Student.objects.get(name__iexact=username, student_id=password)
            # ✅ Only allow login if student has at least 1 certificate
            has_cert = Certificate.objects.filter(student_name=student.name).exists()
            if not has_cert:
                messages.error(request, "Certificate not generated yet for this student.")
                return redirect('student_login')

            # ✅ Save to session
            request.session['student_id'] = student.id
            return redirect('student_dashboard')

        except Student.DoesNotExist:
            messages.error(request, "Invalid name or register number.")

        return render(request, 'student-login.html')
   
#credential verification
@csrf_exempt
def verification_view(request):
    if request.method == "POST":
        credential_id = request.POST.get('credentialId', '').strip()

        if not credential_id or len(credential_id) < 5:
            return JsonResponse({'error': 'Invalid Credential ID format.'}, status=400)

        try:
            certificate = Certificate.objects.get(credential_id=credential_id)
        except Certificate.DoesNotExist:
            return JsonResponse({'error': 'No certificate found for the provided Credential ID.'}, status=404)

        if not certificate.generated_pdf:
            return JsonResponse({'error': 'Certificate PDF is missing. Please contact support.'}, status=500)

        
        data = {
            'student_name': certificate.student_name,
            'credential_id': certificate.credential_id,
            'certificate_type': get_certificate_title(certificate.certificate_type), 
            'course_name': certificate.course_name,     
            'issue_date': certificate.issue_date,       
            'preview_url': certificate.generated_pdf.url,
        }
        return JsonResponse(data, status=200)

    # ✅ Handle GET requests for direct URL
    credential_id = request.GET.get('id')
    certificate_data = None

    if credential_id:
        try:
            certificate = Certificate.objects.get(credential_id=credential_id)
            if certificate.generated_pdf:
                certificate_data = {
                    'student_name': certificate.student_name,
                    'credential_id': certificate.credential_id,
                    'certificate_type': certificate.certificate_type,
                    'course_name': certificate.course_name,
                    'issue_date': certificate.issue_date,
                    'preview_url': certificate.generated_pdf.url,
                }
        except Certificate.DoesNotExist:
            certificate_data = None

    return render(request, 'verification.html', {
        'certificate_data': certificate_data
    })
def get_certificate_title(cert_type):
    cert_type = cert_type.lower()
    if cert_type == "completion":
        return "Completion Certificate"
    elif cert_type == "internship":
        return "Internship Certificate"
    elif cert_type == "offer":
        return "Offer Letter"
    else:
        return "Certificate"


    # ======================
    # 🗑️ Certificate Deletion (Admin only)
    # ======================

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse

@login_required
@user_passes_test(is_admin)
@csrf_exempt
def delete_certificate(request, cert_id):
    if request.method == 'POST':
        cert = get_object_or_404(Certificate, id=cert_id)
        cert.delete()
        return JsonResponse({'status': 'success'}, status=200)
    return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)

@login_required
@user_passes_test(is_admin)
def preview_offer_certificate(request, pk):
    cert = get_object_or_404(Certificate, pk=pk, certificate_type='offer')
    return FileResponse(cert.generated_pdf, content_type='application/pdf')

@login_required
@user_passes_test(is_admin)
def download_offer_certificate(request, pk):
    cert = get_object_or_404(Certificate, pk=pk, certificate_type='offer')
    response = FileResponse(cert.generated_pdf, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{cert.student_name}_offer_certificate.pdf"'
    return response

@login_required
@user_passes_test(is_admin)
def delete_offer_certificate(request, pk):
    if request.method == 'POST':
        cert = get_object_or_404(Certificate, pk=pk, certificate_type='offer')
        cert.delete()
        return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'error'})

    # ======================
    # 🗑️ Admin Edit & Deletion (Admin only)
    # ======================

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.views.decorators.http import require_POST
from .models import AdminUser
from .forms import AdminUserForm


from django.contrib.auth import get_user_model
User = get_user_model()

def edit_admin(request, admin_id):
    admin = get_object_or_404(AdminUser, id=admin_id)
    if request.method == 'POST':
        old_employment_id = admin.employment_id

        # Update AdminUser table
        admin.full_name = request.POST.get('full_name')
        admin.email = request.POST.get('email')
        admin.designation = request.POST.get('designation')
        admin.employment_id = request.POST.get('employment_id')
        admin.phone = request.POST.get('phone')
        admin.save()

        # Update the related auth User table
        try:
            user = User.objects.get(username=admin.email)
            user.email = admin.email

            if admin.employment_id != old_employment_id:
                user.set_password(admin.employment_id)  # New password = new employment ID
                user.save(update_fields=['password', 'email'])  # Ensure changes are saved

        except User.DoesNotExist:
            pass

        messages.success(request, "Admin details updated successfully.")
        return redirect('admin_dashboard')

    return render(request, 'login/edit-admin.html', {'admin': admin})


from django.contrib.auth import get_user_model
User = get_user_model()

def delete_admin(request, admin_id):
    admin = get_object_or_404(AdminUser, id=admin_id)
    try:
        # Delete related User first
        user = User.objects.get(username=admin.email)
        user.delete()
    except User.DoesNotExist:
        pass

    # Delete the AdminUser profile
    admin.delete()

    messages.success(request, "Admin deleted successfully.")
    return redirect('admin_dashboard')


    # ======================
    # 🗑️ Coordiator Edit & Deletion (Admin only)
    # ======================

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.contrib.auth import get_user_model
from .models import Coordinator

User = get_user_model()

def edit_coordinator(request, pk):
    coordinator = get_object_or_404(Coordinator, pk=pk)

    if request.method == 'POST':
        coordinator.full_name = request.POST.get('full_name')
        coordinator.email = request.POST.get('email')
        coordinator.designation = request.POST.get('designation')
        coordinator.employment_id = request.POST.get('employment_id')
        coordinator.phone = request.POST.get('phone', '')

        # Update linked user login details
        user = coordinator.user
        user.username = coordinator.email
        user.email = coordinator.email
        user.set_password(coordinator.employment_id)  # reset password to new emp_id
        user.save()

        coordinator.save()
        messages.success(request, "Coordinator updated successfully!")
        return redirect('admin_dashboard')

    return render(request, 'login/edit_coordinator.html', {'coordinator': coordinator})


def delete_coordinator(request, pk):
    coordinator = get_object_or_404(Coordinator, pk=pk)
    user = coordinator.user  # linked auth user

    coordinator.delete()  # remove coordinator profile
    user.delete()         # remove login access

    messages.success(request, "Coordinator deleted successfully!")
    return redirect('admin_dashboard')

   # ======================
    # 🗑️ Student Deletion (Admin only)
    # ======================
from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages

def delete_certificate(request, cert_id):
    cert = get_object_or_404(Certificate, id=cert_id)
    cert.delete()
    messages.success(request, "")
    return redirect('admin_dashboard')

