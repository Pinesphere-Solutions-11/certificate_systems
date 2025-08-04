from django import views
from django.conf import settings
from django.shortcuts import redirect
from django.urls import path
from .views import add_student, student_login_view
from .views import contact_view
from . import views
from .views import download_certificate

from .views import (
    login_view, logout_view, dashboard_redirect,
    admin_dashboard, coordinator_dashboard, student_dashboard,
    create_offer_letter, create_completion_certificate
)

LOGIN_URL = '/accounts/login/coordinator/'


urlpatterns = [
    path('login/<str:role>/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('dashboard/', dashboard_redirect, name='dashboard_redirect'),
    path('dashboard/admin/', admin_dashboard, name='admin_dashboard'),
    path('dashboard/coordinator/', coordinator_dashboard, name='coordinator_dashboard'),
    path('dashboard/student/', student_dashboard, name='student_dashboard'),
    path('student/add/', add_student, name='add_student'),
    path('certificate/offer/bulk-upload/', views.bulk_offer_upload, name='bulk_offer_upload'),
    path('certificate/completion/bulk-upload/', views.bulk_completion_upload, name='bulk_completion_upload'),
    path('certificate/offer/create/', create_offer_letter, name='create_offer_letter'),
    path('certificate/completion/create/', create_completion_certificate, name='create_completion_certificate'),
    path('accounts/login/', lambda request: redirect('login', role='coordinator')),
    path('contact/', contact_view, name='contact'),
    path('certificate/download/<int:cert_id>/', download_certificate, name='download_certificate'),
    path('accounts/ping/', views.ping_session, name='ping_session'),
    path('dashboard/admin/template-editor/', views.template_editor, name='template_editor'),
    path('admin/template-editor/save/', views.save_template, name='save_template'),
    path('admin/create-template/', views.create_certificate_template, name='create_certificate_template'),
    path('admin/management/', views.admin_management_panel, name='admin_management'),
] 
