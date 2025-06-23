from django.urls import path
from .views import (
    login_view, logout_view, dashboard_redirect,
    admin_dashboard, coordinator_dashboard, student_dashboard
)

urlpatterns = [
    path('login/<str:role>/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('dashboard/', dashboard_redirect, name='dashboard_redirect'),
    path('dashboard/admin/', admin_dashboard, name='admin_dashboard'),
    path('dashboard/coordinator/', coordinator_dashboard, name='coordinator_dashboard'),
    path('dashboard/student/', student_dashboard, name='student_dashboard'),
]
