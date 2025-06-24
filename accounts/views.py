from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from .forms import LoginForm
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required, user_passes_test
from .forms import CoordinatorForm, StudentForm, AdminUserForm
from django.http import JsonResponse
from .models import Certificate
import datetime

User = get_user_model()

def login_view(request, role):
    # Always logout before showing login screen (optional safety)
    logout(request)

    template_map = {
        'admin': 'login-admin.html',
        'coordinator': 'login-coordinator.html',
        'student': 'login-student.html',
    }

    # Default to student if unknown role
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


@login_required
def dashboard_redirect(request):
    if request.user.role == 'admin':
        return redirect('admin_dashboard')
    elif request.user.role == 'coordinator':
        return redirect('coordinator_dashboard')
    else:
        return redirect('student_dashboard')

def logout_view(request):
    logout(request)
    return redirect('login', role='student')

def is_admin(user):
    return user.is_authenticated and user.role == 'admin'

def is_coordinator(user):
    return user.is_authenticated and user.role == 'coordinator'

def is_student(user):
    return user.is_authenticated and user.role == 'student'


from django.shortcuts import render, redirect
from .forms import CoordinatorForm, StudentForm, AdminUserForm
from .models import Coordinator, Student, AdminUser
from django.contrib import messages

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

    # Count values
    context = {
        'coordinator_count': Coordinator.objects.count(),
        'student_count': Student.objects.count(),
        'total_certificates': 0  # Replace with actual count if applicable
    }
    return render(request, 'login/admin-dashboard.html', context)



@login_required
@user_passes_test(is_coordinator)
def coordinator_dashboard(request):
    return render(request, 'login/coordinator-dashboard.html')

@login_required
@user_passes_test(is_student)
def student_dashboard(request):
    return render(request, 'login/student-dashboard.html')


@login_required
@user_passes_test(is_coordinator)
def create_offer_letter(request):
    if request.method == 'POST':
        data = request.POST

        cert = Certificate.objects.create(
            certificate_type='offer',
            title=data.get('title'),
            student_name=data.get('student_name'),
            student_id=data.get('student_id'),
            department=data.get('department'),
            college=data.get('college'),
            location=data.get('location'),
            course_name=data.get('course_name'),
            duration=data.get('duration'),
            completion_date=data.get('completion_date'),
            director_name=data.get('director')
        )

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

        cert = Certificate.objects.create(
            certificate_type='completion',
            title=data.get('title'),
            student_name=data.get('student_name'),
            student_id=data.get('student_id'),
            department=data.get('department'),
            college=data.get('college'),
            location=data.get('location'),
            course_name=data.get('course_name'),
            duration=data.get('duration'),
            completion_date=data.get('completion_date'),
            director_name=data.get('director')
        )

        return JsonResponse({
            'status': 'success',
            'message': 'Internship Certificate created successfully!',
            'certificate_number': cert.certificate_number,
            'student': cert.student_name,
            'course': cert.course_name,
            'date': cert.completion_date.strftime('%Y-%m-%d')
        })

    return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)
