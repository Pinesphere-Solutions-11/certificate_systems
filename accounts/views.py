from audioop import reverse
import csv
from io import BytesIO
import json
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.http import Http404, HttpResponse, JsonResponse, FileResponse
from weasyprint import HTML
from django.core.files.base import File
from django.conf import settings
from datetime import datetime
from .forms import StudentForm
from .models import ContactMessage, Certificate, Coordinator, Student, TemplateSetting, User
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
from django.db import IntegrityError
from django.core.files.storage import default_storage
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.cache import cache_control
from django.views.decorators.cache import cache_control, never_cache
from dateutil import parser
import pandas as pd
import io
from .utils import get_template_for_certificate
# Function for admin only login
def is_admin(user):
    return user.is_authenticated and user.role == 'admin'



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
    # Kill session & logout
    logout(request)
    request.session.flush()  # double ensure session data is removed

    # Redirect to home (or login page if you want)
    response = redirect('index')

    # Remove session cookie
    response.delete_cookie('sessionid')
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

from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str

def set_password(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is None or not default_token_generator.check_token(user, token):
        messages.error(request, "The password set link is invalid or expired.")
        return redirect('index')

    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        confirm = request.POST.get('confirm_password')
        if not new_password or new_password != confirm:
            messages.error(request, "Passwords do not match.")
            return render(request, 'login/set_password.html', {'valid': True})
        # Set the password and lock future changes
        user.set_password(new_password)
        user.must_set_password = False
        user.password_locked = True
        user.save()
        messages.success(request, "Password set successfully. Please log in.")
        return redirect('index')  # or appropriate login route
    # GET -> render form
    return render(request, 'login/set_password.html', {'valid': True})


# =========================
# 📊 ADMIN DASHBOARD
# =========================
from django.http import JsonResponse
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Q
from .forms import  StudentForm
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.paginator import Paginator
from accounts.models import Certificate, Student, Coordinator, AdminUser, User 
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse


@login_required(login_url="index")
@user_passes_test(is_admin)
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
@never_cache
def admin_dashboard(request):
    
    certificates = Certificate.objects.all().order_by('id')
    
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
                return JsonResponse({'status': 'error', 'message': 'Full name, email, and employment ID are required.'}, status=400)

            # Only check Coordinator table (per your request)
            if Coordinator.objects.filter(email=email).exists():
                return JsonResponse({'status': 'error', 'message': 'Email already exists.'}, status=400)

            # Role priority mapping
            role_priority = {'student': 1, 'coordinator': 2, 'admin': 3}
            desired_role = 'coordinator'

            # Reuse existing User if present, otherwise create new user
            user = User.objects.filter(Q(username=email) | Q(email=email)).first()
            if user:
                prev_role = getattr(user, 'role', 'student')
                role_changed = False
                # escalate role if desired has higher privilege
                if role_priority.get(desired_role, 0) > role_priority.get(prev_role, 0):
                    user.role = desired_role
                    user.save()
                    role_changed = True

                # Send link if: user has no usable password OR must_set_password flagged OR role was escalated
                send_link = (not user.has_usable_password()) or getattr(user, 'must_set_password', False) or role_changed
            else:
                # create new user and mark as must set password
                user = User.objects.create_user(username=email, email=email)
                user.set_unusable_password()
                user.must_set_password = True
                user.password_locked = False
                user.role = desired_role
                user.save()
                send_link = True

            # Create Coordinator profile
            try:
                Coordinator.objects.create(
                    user=user,
                    full_name=full_name,
                    email=email,
                    designation=designation,
                    employment_id=employment_id,
                    phone=phone
                )
            except IntegrityError:
                # Profile conflict (unique email/employment_id) — report to UI
                return JsonResponse({'status': 'error', 'message': 'Coordinator record conflicts (email/employment ID).'}, status=400)

            # Send set-password link if required
            if send_link:
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                token = default_token_generator.make_token(user)
                set_password_url = request.build_absolute_uri(
                    reverse('set_password', kwargs={'uidb64': uid, 'token': token})
                )

                subject = "Set your account password"
                message = f"Hello {full_name},\n\nPlease set your account password by clicking the link below:\n\n{set_password_url}\n\nThis link will expire soon."
                send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email], fail_silently=False)

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

            # Only check AdminUser table (per your request)
            if AdminUser.objects.filter(email=email).exists():
                return JsonResponse({'status': 'error', 'message': 'Email already exists.'}, status=400)

            # Role priority mapping
            role_priority = {'student': 1, 'coordinator': 2, 'admin': 3}
            desired_role = 'admin'

            # Reuse existing User if present, otherwise create new user
            user = User.objects.filter(Q(username=email) | Q(email=email)).first()
            if user:
                prev_role = getattr(user, 'role', 'student')
                role_changed = False
                # escalate role if desired has higher privilege
                if role_priority.get(desired_role, 0) > role_priority.get(prev_role, 0):
                    user.role = desired_role
                    user.save()
                    role_changed = True

                # Send link if: user has no usable password OR must_set_password flagged OR role was escalated
                send_link = (not user.has_usable_password()) or getattr(user, 'must_set_password', False) or role_changed
            else:
                # create new user and mark as must set password
                user = User.objects.create_user(username=email, email=email)
                user.set_unusable_password()
                user.must_set_password = True
                user.password_locked = False
                user.role = desired_role
                user.save()
                send_link = True

            # Create Admin profile
            try:
                AdminUser.objects.create(
                    user=user,
                    full_name=full_name,
                    email=email,
                    designation=designation,
                    employment_id=employment_id,
                    phone=phone
                )
            except IntegrityError:
                return JsonResponse({'status': 'error', 'message': 'Admin record conflicts (email/employment ID).'}, status=400)

            # Send set-password link if required
            if send_link:
                uid = urlsafe_base64_encode(force_bytes(user.pk))
                token = default_token_generator.make_token(user)
                set_password_url = request.build_absolute_uri(
                    reverse('set_password', kwargs={'uidb64': uid, 'token': token})
                )

                subject = "Set your account password"
                message = f"Hello {full_name},\n\nPlease set your account password by clicking the link below:\n\n{set_password_url}\n\nThis link will expire soon."
                send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email], fail_silently=False)

            if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                return JsonResponse({'status': 'success', 'message': 'Admin added successfully!'})

            messages.success(request, 'Admin added successfully!')
            return redirect('admin_dashboard')
                
        else:
            return JsonResponse({'status': 'error', 'message': form.errors.as_json()}, status=400)

    try:
        setting = TemplateSetting.objects.get(certificate_type="completion")
        current_template = setting.selected_template
    except TemplateSetting.DoesNotExist:
        current_template = "default"

    
    
    context = {
        "completion_certificates": page_obj.object_list,  # only current page records
        "offer_certificates": page_obj.object_list,
        "page_obj": page_obj,
        'certificates': page_obj,
        'page_obj': page_obj,
        'cert_type': cert_type,
        'student_name': student_name,
        "current_template": current_template,
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
    
    full_name = request.session.get('full_name')
    coordinator = Coordinator.objects.filter(full_name=full_name)
    
    # Initial queryset: all certificates created by the logged-in coordinator
    certificates = Certificate.objects.filter(created_by=request.user).order_by('-created_at')
    
    offer_certificates = Certificate.objects.filter(certificate_type='offer')
    completion_certificates = Certificate.objects.filter(certificate_type='completion')

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
        
    full_name = coordinator.full_name if coordinator.exists() else "Coordinator"

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
        'full_name': full_name,
        'student_name': student_name,
        'course_name': course_name,
        'offer_certificates': offer_certificates,
        'completion_certificates': completion_certificates,
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
            template_choice=data.get('completionTemplate', 'default'),  # save selection
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

        template_name = get_template_for_certificate("completion")
        generate_certificate_pdf(cert, template_name)

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


# views.py (replace existing bulk_offer_upload)
@csrf_exempt
@login_required
@user_passes_test(is_coordinator)
def bulk_offer_upload(request):
    """
    Flow:
    - Parse file into list of row dicts (reader_list)
    - Detect duplicates (in-file and in DB)
    - If duplicates found and action != 'skip' -> return 409 + duplicate details
    - If action == 'skip' or no duplicates -> create certificates skipping duplicates
    """
    if request.method == 'POST' and request.FILES.get('csvFile'):
        action = request.POST.get('action')  # None | 'skip' | 'cancel' | 'reupload'
        file_obj = request.FILES['csvFile']
        file_name = file_obj.name.lower()

        # parse file into a list for two-pass processing
        try:
            if file_name.endswith('.csv'):
                try:
                    decoded = file_obj.read().decode('utf-8').splitlines()
                except UnicodeDecodeError:
                    file_obj.seek(0)
                    decoded = file_obj.read().decode('latin-1').splitlines()
                reader_list = list(csv.DictReader(decoded))
            elif file_name.endswith(('.xls', '.xlsx')):
                df = pd.read_excel(file_obj)
                reader_list = df.to_dict(orient='records')
            else:
                return JsonResponse({'status': 'error', 'message': 'Unsupported file type'}, status=400)
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': f'Failed to parse file: {str(e)}'}, status=400)

        # duplicate detection
        duplicates = []
        seen_ids = set()
        for idx, row in enumerate(reader_list):
            sid = str(row.get('Student ID', '')).strip()
            sname = str(row.get('Student Name', '')).strip()
            # missing id -> mark as invalid row (optional)
            if not sid:
                duplicates.append({'row': idx + 1, 'student_id': sid, 'student_name': sname,
                                   'course': row.get('Course Name', ''), 'reason': 'missing_student_id'})
                continue

            # duplicate in uploaded file (keep first occurrence)
            if sid in seen_ids:
                duplicates.append({'row': idx + 1, 'student_id': sid, 'student_name': sname,
                                   'course': row.get('Course Name', ''), 'reason': 'duplicate_in_file'})
                continue

            # duplicate in DB: student_id + student_name match
            if Certificate.objects.filter(student_id=sid, student_name__iexact=sname).exists():
                duplicates.append({'row': idx + 1, 'student_id': sid, 'student_name': sname,
                                   'course': row.get('Course Name', ''), 'reason': 'exists_in_db'})
            seen_ids.add(sid)

        # If duplicates found and user hasn't chosen to skip, return 409 with details
        if duplicates and action != 'skip':
            return JsonResponse({'status': 'conflict', 'message': 'Duplicates detected', 'duplicates': duplicates}, status=409)

        # Otherwise create certificates (skip duplicates):
        created = []
        seen_ids = set()
        for idx, row in enumerate(reader_list):
            sid = str(row.get('Student ID', '')).strip()
            sname = str(row.get('Student Name', '')).strip()

            if not sid:
                continue  # skip invalid rows
            if sid in seen_ids:
                continue  # skip duplicate_in_file (keep first only)
            if Certificate.objects.filter(student_id=sid, student_name__iexact=sname).exists():
                if action == 'skip':
                    seen_ids.add(sid)
                    continue

            # create certificate (use your existing mapping and parser)
            try:
                cert = Certificate.objects.create(
                    certificate_type='offer',
                    title=row.get('Title', '') or '',
                    student_name=sname,
                    student_id=sid,
                    department=row.get('Department', ''),
                    degree=row.get('Degree', ''),
                    college=row.get('College', ''),
                    location=row.get('Location', ''),
                    course_name=row.get('Course Name', ''),
                    duration=row.get('Duration', ''),
                    start_date=parser.parse(str(row.get('Start Date'))) if row.get('Start Date') else None,
                    end_date=parser.parse(str(row.get('End Date'))) if row.get('End Date') else None,
                    completion_date=parser.parse(str(row.get('Issue Date'))) if row.get('Issue Date') else None,
                    issue_date=parser.parse(str(row.get('Issue Date'))) if row.get('Issue Date') else None,
                    director_name=row.get('Director Name', ''),
                    created_by=request.user
                )
                generate_certificate_pdf(cert, 'login/internship_offer.html')
                created.append(cert.pk)
                seen_ids.add(sid)
            except Exception as e:
                # If you want, log the row/index error; continue so other rows still process
                continue

        return JsonResponse({'status': 'success', 'created': created}, status=200)

    return JsonResponse({'status': 'error', 'message': 'CSV/Excel file not found'}, status=400)


@csrf_exempt
@login_required
@user_passes_test(is_coordinator)
def bulk_completion_upload(request):
    action = request.POST.get('action')  # None | 'skip'
    if request.method == 'POST' and request.FILES.get('csvFile'):
        file_obj = request.FILES['csvFile']
        file_name = file_obj.name.lower()

        try:
            if file_name.endswith('.csv'):
                try:
                    decoded = file_obj.read().decode('utf-8').splitlines()
                except UnicodeDecodeError:
                    file_obj.seek(0)
                    decoded = file_obj.read().decode('latin-1').splitlines()
                reader_list = list(csv.DictReader(decoded))
            elif file_name.endswith(('.xls', '.xlsx')):
                df = pd.read_excel(file_obj)
                reader_list = df.to_dict(orient='records')
            else:
                return JsonResponse({'status': 'error', 'message': 'Unsupported file type'}, status=400)
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': f'Failed to parse file: {str(e)}'}, status=400)

        # duplicate detection
        duplicates = []
        seen_ids = set()
        for idx, row in enumerate(reader_list):
            sid = str(row.get('Student ID', '')).strip()
            sname = str(row.get('Student Name', '')).strip()
            if not sid:
                duplicates.append({'row': idx + 1, 'student_id': sid, 'student_name': sname,
                                   'course': row.get('Course Name', ''), 'reason': 'missing_student_id'})
                continue
            if sid in seen_ids:
                duplicates.append({'row': idx + 1, 'student_id': sid, 'student_name': sname,
                                   'course': row.get('Course Name', ''), 'reason': 'duplicate_in_file'})
                continue
            if Certificate.objects.filter(student_id=sid, student_name__iexact=sname).exists():
                duplicates.append({'row': idx + 1, 'student_id': sid, 'student_name': sname,
                                   'course': row.get('Course Name', ''), 'reason': 'exists_in_db'})
            seen_ids.add(sid)

        if duplicates and action != 'skip':
            return JsonResponse({'status': 'conflict', 'message': 'Duplicates detected', 'duplicates': duplicates}, status=409)

        created = []
        seen_ids = set()
        for idx, row in enumerate(reader_list):
            sid = str(row.get('Student ID', '')).strip()
            sname = str(row.get('Student Name', '')).strip()
            if not sid:
                continue
            if sid in seen_ids:
                continue
            if Certificate.objects.filter(student_id=sid, student_name__iexact=sname).exists():
                if action == 'skip':
                    seen_ids.add(sid)
                    continue
            try:
                cert = Certificate.objects.create(
                    certificate_type='completion',
                    title=row.get('Title', '') or '',
                    student_name=sname,
                    student_id=sid,
                    department=row.get('Department', ''),
                    degree=row.get('Degree', ''),
                    college=row.get('College', ''),
                    location=row.get('Location', ''),
                    course_name=row.get('Course Name', ''),
                    duration=row.get('Duration', ''),
                    start_date=parser.parse(str(row.get('Start Date'))) if row.get('Start Date') else None,
                    end_date=parser.parse(str(row.get('End Date'))) if row.get('End Date') else None,
                    completion_date=parser.parse(str(row.get('Issue Date'))) if row.get('Issue Date') else None,
                    issue_date=parser.parse(str(row.get('Issue Date'))) if row.get('Issue Date') else None,
                    director_name=row.get('Director Name', ''),
                    created_by=request.user
                )
                template_name = get_template_for_certificate("completion")
                generate_certificate_pdf(cert, template_name)
                created.append(cert.pk)
                seen_ids.add(sid)
            except Exception:
                continue

        return JsonResponse({'status': 'success', 'created': created}, status=200)

    return JsonResponse({'status': 'error', 'message': 'CSV/Excel file not found'}, status=400)

@login_required
@user_passes_test(is_admin)
def update_template_setting(request):
    if request.method == "POST":
        cert_type = request.POST.get("certificate_type")
        template = request.POST.get("template_choice")

        if not cert_type or not template:
            return JsonResponse({"status": "error", "message": "Missing parameters"}, status=400)

        setting, _ = TemplateSetting.objects.update_or_create(
            certificate_type=cert_type,
            defaults={"selected_template": template}
        )

        return JsonResponse({"status": "success", "selected": template})

    return JsonResponse({"status": "error", "message": "Invalid request"}, status=400)



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

from .models import StudentQuery

def submit_query(request):
    
    if request.method == "POST":
        # check if student is logged in
        student_id = request.session.get("student_id")
        student_name = request.session.get("student_name")

        if not student_id or not student_name:
            return JsonResponse(
                {"status": "error", "message": "You must be logged in to submit a query."},
                status=403
            )

        subject = request.POST.get("subject")
        query_text = request.POST.get("query")
        certificate_type = request.POST.get("certificateType")  # ✅ new field
        

        if not subject or not query_text:
            return JsonResponse(
                {"status": "error", "message": "All fields are required."},
                status=400
            )
            
        cert = Certificate.objects.filter(student_id=student_id, certificate_type=certificate_type).last()

        # Save query
        StudentQuery.objects.create(
            student_id=student_id,
            student_name=student_name,
            subject=subject,
            query=query_text,
            certificate=cert,
            certificate_type=certificate_type
        )

        return JsonResponse(
            {"status": "success", "message": "Query submitted successfully!"}
        )

    return JsonResponse({"status": "error", "message": "Invalid request"}, status=400)



def query_list(request):
    role = getattr(request.user, "role", None)

    if role in ("admin", "coordinator"):
        queries = StudentQuery.objects.all().order_by("-created_at")
    else:
        student_id = request.session.get("student_id")
        student_name = request.session.get("student_name")

        if not student_id or not student_name:
            return JsonResponse({"queries": []})  # not logged in

        queries = StudentQuery.objects.filter(
            student_id=str(student_id).strip(),
            student_name=str(student_name).strip()
        ).order_by("-created_at")

    data = [
        {
            "id": q.id,
            "subject": q.subject,
            "query_text": q.query,
            "resolved": q.resolved,
            "student": q.student_name,
            "student_id": q.student_id,
            "certificate_type": q.certificate_type,
            "certificate_id": q.certificate.id if q.certificate else None, 
            "created_at": q.created_at.strftime("%Y-%m-%d %H:%M"),
        }
        for q in queries
    ]
    return JsonResponse({"queries": data})


@user_passes_test(is_admin_or_coordinator)
def resolve_query(request, pk):
    try:
        query = StudentQuery.objects.get(pk=pk)
        query.resolved = True
        query.save()
        return JsonResponse({"status": "success", "message": "Query marked as resolved"})
    except StudentQuery.DoesNotExist:
        return JsonResponse({"status": "error", "message": "Query not found"}, status=404)



@user_passes_test(is_admin_or_coordinator)
def delete_query(request, pk):
    try:
        query = StudentQuery.objects.get(pk=pk)
        query.delete()
        return JsonResponse({"status": "success", "message": "Query deleted"})
    except StudentQuery.DoesNotExist:
        return JsonResponse({"status": "error", "message": "Query not found"}, status=404)

@login_required
@user_passes_test(is_admin)
def edit_certificate(request, pk):
    certificate = get_object_or_404(Certificate, pk=pk)

    if request.method == 'POST':
        data = request.POST
        signature_file = request.FILES.get('offerSignature') or certificate.signature

        try:
            start_date = datetime.strptime(data.get('offerStartDate'), '%Y-%m-%d').date()
            end_date   = datetime.strptime(data.get('offerEndDate'),   '%Y-%m-%d').date()
            issue_date = datetime.strptime(data.get('offerIssueDate'), '%Y-%m-%d').date()
        except Exception:
            return JsonResponse({'status': 'error', 'message': 'Invalid date format'}, status=400)

        # 🔹 Update fields
        certificate.title = data.get('offerTitle')
        certificate.student_name = data.get('offerStudentName')
        certificate.student_id = data.get('offerRegisterNumber')
        certificate.degree = data.get('offerDegree')
        certificate.department = data.get('offerDepartment')
        certificate.college = data.get('offerCollege')
        certificate.location = data.get('offerLocation')
        certificate.course_name = data.get('offerCourseName')
        certificate.duration = data.get('offerDuration')
        certificate.start_date = start_date
        certificate.end_date = end_date
        certificate.issue_date = issue_date
        certificate.director_name = data.get('offerDirector')
        certificate.signature = signature_file

        # 🔹 Delete old PDF if exists
        if certificate.generated_pdf:
            old_pdf_path = certificate.generated_pdf.path
            if os.path.exists(old_pdf_path):
                os.remove(old_pdf_path)
            certificate.generated_pdf.delete(save=False)

        # 🔹 Save first so regeneration attaches to this cert
        certificate.save()

        # 🔹 Decide template depending on type
        if certificate.certificate_type == "offer":
            template_name = "login/internship_offer.html"
        else:
            template_name = get_template_for_certificate("completion")

        # 🔹 Regenerate new PDF
        generate_certificate_pdf(certificate, template_name)
        
        # 🔹 Auto-resolve related query
        StudentQuery.objects.filter(certificate=certificate, resolved=False).update(resolved=True)

        messages.success(request, "Certificate updated and regenerated successfully!")
        return redirect('admin_dashboard')

    # ✅ Prefill form with certificate data
    return render(request, 'login/edit-certificate.html', {'certificate': certificate})


@login_required
@user_passes_test(is_coordinator)
def edit_certificate(request, pk):
    certificate = get_object_or_404(Certificate, pk=pk)

    if request.method == 'POST':
        data = request.POST
        signature_file = request.FILES.get('offerSignature') or certificate.signature

        try:
            start_date = datetime.strptime(data.get('offerStartDate'), '%Y-%m-%d').date()
            end_date   = datetime.strptime(data.get('offerEndDate'),   '%Y-%m-%d').date()
            issue_date = datetime.strptime(data.get('offerIssueDate'), '%Y-%m-%d').date()
        except Exception:
            return JsonResponse({'status': 'error', 'message': 'Invalid date format'}, status=400)

        # 🔹 Update fields
        certificate.title = data.get('offerTitle')
        certificate.student_name = data.get('offerStudentName')
        certificate.student_id = data.get('offerRegisterNumber')
        certificate.degree = data.get('offerDegree')
        certificate.department = data.get('offerDepartment')
        certificate.college = data.get('offerCollege')
        certificate.location = data.get('offerLocation')
        certificate.course_name = data.get('offerCourseName')
        certificate.duration = data.get('offerDuration')
        certificate.start_date = start_date
        certificate.end_date = end_date
        certificate.issue_date = issue_date
        certificate.director_name = data.get('offerDirector')
        certificate.signature = signature_file

        # 🔹 Delete old PDF if exists
        if certificate.generated_pdf:
            old_pdf_path = certificate.generated_pdf.path
            if os.path.exists(old_pdf_path):
                os.remove(old_pdf_path)
            certificate.generated_pdf.delete(save=False)

        # 🔹 Save first so regeneration attaches to this cert
        certificate.save()

        # 🔹 Decide template depending on type
        if certificate.certificate_type == "offer":
            template_name = "login/internship_offer.html"
        else:
            template_name = get_template_for_certificate("completion")

        # 🔹 Regenerate new PDF
        generate_certificate_pdf(certificate, template_name)
        
        # 🔹 Auto-resolve related query
        StudentQuery.objects.filter(certificate=certificate, resolved=False).update(resolved=True)

        messages.success(request, "Certificate updated and regenerated successfully!")
        return redirect('coordinator_dashboard')

    # ✅ Prefill form with certificate data
    return render(request, 'login/edit-certificate.html', {'certificate': certificate})


from django.views.decorators.http import require_GET

@require_GET
def certificates_by_student(request, student_id):
    student_name = request.GET.get("student_name", "").strip()
    if not student_name:
        return JsonResponse({"status": "error", "message": "Student name required"}, status=400)

    certificates = Certificate.objects.filter(
        student_id=student_id.strip(),
        student_name=student_name.strip()
    ).order_by("-issue_date")

    data = [
        {
            "id": c.id,
            "certificate_type": c.certificate_type,
            "student_name": c.student_name,
            "student_id": c.student_id,
            "course_name" : c.course_name,
            "issue_date": c.issue_date.strftime("%Y-%m-%d") if c.issue_date else None,
        }
        for c in certificates
    ]

    return JsonResponse({"status": "success", "certificates": data})

@require_GET
def certificate_detail(request, pk):
    try:
        c = Certificate.objects.get(pk=pk)
    except Certificate.DoesNotExist:
        return JsonResponse({"status": "error", "message": "Certificate not found"}, status=404)

    data = {
        "id": c.id,
        "title": c.title,
        "student_name": c.student_name,
        "student_id": c.student_id,
        "degree": c.degree,
        "department": c.department,
        "college": c.college,
        "location": c.location,
        "course_name": c.course_name,
        "duration": c.duration,
        "start_date": c.start_date.strftime("%Y-%m-%d") if c.start_date else "",
        "end_date": c.end_date.strftime("%Y-%m-%d") if c.end_date else "",
        "issue_date": c.issue_date.strftime("%Y-%m-%d") if c.issue_date else "",
        "director_name": c.director_name,
    }
    return JsonResponse({"status": "success", "certificate": data})
@login_required
@user_passes_test(is_admin)
def generate_completion(request, pk):
    # Fetch the offer certificate first
    offer_cert = get_object_or_404(Certificate, pk=pk, certificate_type="offer")

    if request.method == "POST":
        data = request.POST
        signature_file = request.FILES.get("completionSignature")

        try:
            start_date = datetime.strptime(data.get("completionStartDate"), "%Y-%m-%d").date()
            end_date   = datetime.strptime(data.get("completionEndDate"), "%Y-%m-%d").date()
            issue_date = datetime.strptime(data.get("completionIssueDate"), "%Y-%m-%d").date()
        except Exception:
            messages.error(request, "Invalid date format")
            return redirect("admin_dashboard")

        # Create a new Completion Certificate
        completion_cert = Certificate.objects.create(
            certificate_type="completion",
            template_choice=data.get("completionTemplate", "default"),
            title=data.get("completionTitle") or f"Completion of {offer_cert.course_name}",
            student_name=offer_cert.student_name,
            student_id=offer_cert.student_id,
            degree=offer_cert.degree,
            department=offer_cert.department,
            college=offer_cert.college,
            location=offer_cert.location,
            course_name=offer_cert.course_name,
            duration=offer_cert.duration,
            start_date=start_date,
            end_date=end_date,
            completion_date=issue_date,
            issue_date=issue_date,
            director_name=data.get("completionDirector") or offer_cert.director_name,
            signature=signature_file or offer_cert.signature,
            created_by=request.user,
        )

        # Generate PDF for the new certificate
        template_name = get_template_for_certificate("completion")
        generate_certificate_pdf(completion_cert, template_name)

        # Show success on admin dashboard
        messages.success(request, f"Completion Certificate generated successfully for {completion_cert.student_name}!")
        return redirect("admin_dashboard")

    # If GET → show the prefilled form (like edit-certificate)
    return render(request, "login/generate_completion.html", {"certificate": offer_cert})

@login_required
@user_passes_test(is_coordinator)
def generate_completion(request, pk):
    # Fetch the offer certificate first
    offer_cert = get_object_or_404(Certificate, pk=pk, certificate_type="offer")

    if request.method == "POST":
        data = request.POST
        signature_file = request.FILES.get("completionSignature")

        try:
            start_date = datetime.strptime(data.get("completionStartDate"), "%Y-%m-%d").date()
            end_date   = datetime.strptime(data.get("completionEndDate"), "%Y-%m-%d").date()
            issue_date = datetime.strptime(data.get("completionIssueDate"), "%Y-%m-%d").date()
        except Exception:
            messages.error(request, "Invalid date format")
            return redirect("admin_dashboard")

        # Create a new Completion Certificate
        completion_cert = Certificate.objects.create(
            certificate_type="completion",
            template_choice=data.get("completionTemplate", "default"),
            title=data.get("completionTitle") or f"Completion of {offer_cert.course_name}",
            student_name=offer_cert.student_name,
            student_id=offer_cert.student_id,
            degree=offer_cert.degree,
            department=offer_cert.department,
            college=offer_cert.college,
            location=offer_cert.location,
            course_name=offer_cert.course_name,
            duration=offer_cert.duration,
            start_date=start_date,
            end_date=end_date,
            completion_date=issue_date,
            issue_date=issue_date,
            director_name=data.get("completionDirector") or offer_cert.director_name,
            signature=signature_file or offer_cert.signature,
            created_by=request.user,
        )

        # Generate PDF for the new certificate
        template_name = get_template_for_certificate("completion")
        generate_certificate_pdf(completion_cert, template_name)

        # Show success on admin dashboard
        messages.success(request, f"Completion Certificate generated successfully for {completion_cert.student_name}!")
        return redirect("coordinator_dashboard")

    # If GET → show the prefilled form (like edit-certificate)
    return render(request, "login/generate_completion.html", {"certificate": offer_cert})


from django.http import FileResponse
import mimetypes

def preview_certificate(request, pk):
    cert = get_object_or_404(Certificate, pk=pk)

    # Ensure PDF is generated
    if not cert.generated_pdf:
        if cert.certificate_type == "offer":
            template_name = "login/internship_offer.html"
        else:
            template_name = get_template_for_certificate("completion")
        generate_certificate_pdf(cert, template_name)

    # Serve PDF inline
    pdf_path = cert.generated_pdf.path
    pdf_file = open(pdf_path, "rb")

    mime_type, _ = mimetypes.guess_type(pdf_path)
    response = FileResponse(pdf_file, content_type=mime_type or "application/pdf")
    response["Content-Disposition"] = f'inline; filename="{cert.certificate_number}.pdf"'
    return response


