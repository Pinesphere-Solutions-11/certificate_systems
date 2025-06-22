from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from .forms import LoginForm
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.urls import reverse
from django.contrib.auth import get_user_model

User = get_user_model()

def login_view(request, role):
    if request.user.is_authenticated:
        return redirect('dashboard_redirect')

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
