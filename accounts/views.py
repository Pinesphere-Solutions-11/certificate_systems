from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from .forms import LoginForm
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required, user_passes_test
from .forms import CoordinatorForm, StudentForm, AdminUserForm

User = get_user_model()

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

    if request.method == 'POST' and form.is_valid():
        user = form.get_user()
        if user.role != role:
            messages.error(request, "You are not authorized to log in as this role.")
        else:
            login(request, user)
            return redirect('dashboard_redirect')

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



@login_required
@user_passes_test(is_admin)
def admin_dashboard(request):
    coordinator_form = CoordinatorForm()
    student_form = StudentForm()
    admin_form = AdminUserForm()

    if request.method == 'POST':
        form_type = request.POST.get('form_type')

        if form_type == 'coordinator':
            coordinator_form = CoordinatorForm(request.POST)
            if coordinator_form.is_valid():
                coordinator_form.save()
        elif form_type == 'student':
            student_form = StudentForm(request.POST)
            if student_form.is_valid():
                student_form.save()
        elif form_type == 'admin':
            admin_form = AdminUserForm(request.POST)
            if admin_form.is_valid():
                admin_form.save()
            else:
                print(admin_form.errors)
    context = {
        'coordinator_form': coordinator_form,
        'student_form': student_form,
        'admin_form': admin_form,
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