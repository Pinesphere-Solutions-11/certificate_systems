import csv
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.http import Http404, HttpResponse, JsonResponse, FileResponse
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

def is_admin(user):
    return user.is_authenticated and user.role == 'admin'

@login_required
@user_passes_test(is_admin)
def template_editor(request):
    return render(request, 'admin/create_certificate_template.html')

@login_required
@user_passes_test(is_admin)
def save_template(request):
    if request.method == 'POST':
        name = request.POST.get('template_name')
        certificate_type = request.POST.get('certificate_type')
        html_content = request.POST.get('html_content')
        background_image = request.FILES.get('background_image')

        # Create or update template
        template, created = CertificateTemplate.objects.update_or_create(
            name=name,
            defaults={
                'certificate_type': certificate_type,
                'html_content': html_content,
                'background_image': background_image if background_image else None,
            }
        )
        return JsonResponse({'status': 'success', 'message': 'Template saved successfully'})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})

@user_passes_test(is_admin, login_url='login')
def create_certificate_template(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        template_type = request.POST.get('template_type')
        content_html = request.POST.get('content_html')

        background_image = request.FILES.get('background_image')
        if background_image:
            image_path = default_storage.save(f'templates/backgrounds/{background_image.name}', background_image)
        else:
            image_path = None

        CertificateTemplate.objects.create(
            name=name,
            template_type=template_type,
            content_html=content_html,
            background_image=image_path
        )
        return render(request, 'admin/close_window.html')  # close popup page after saving
    return render(request, 'admin/create_certificate_template.html')
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


@csrf_exempt  
def logout_view(request):
    logout(request)
    return redirect('index')


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

            if not all([full_name, email, designation, employment_id]):
                return JsonResponse({'status': 'error', 'message': 'All fields except phone are required.'}, status=400)

            if User.objects.filter(username=email).exists():
                return JsonResponse({'status': 'error', 'message': 'Email already exists.'}, status=400)

            # Create the user account
            user = User.objects.create_user(
                username=email,
                email=email,
                password=employment_id,
                role='coordinator'  # Optional: only if your User model has a 'role' field
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
            form = AdminUserForm(request.POST)
            if form.is_valid():
                admin = form.save(commit=False)
                admin.password = make_password(form.cleaned_data['password'])  # Hash the password
                admin.save()
                return JsonResponse({'status': 'success', 'message': 'Admin added successfully!'})
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

        return JsonResponse({'status': 'success', 'created': created})
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

        return JsonResponse({'status': 'success', 'created': created})
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
   
