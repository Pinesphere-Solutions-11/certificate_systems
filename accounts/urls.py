from django.urls import path
from django.shortcuts import redirect
from django.conf import settings
from . import views
from .views import (
    add_student, student_login_view, verification_view, contact_view, download_certificate,
    login_view, logout_view, dashboard_redirect,
    admin_dashboard, coordinator_dashboard, student_dashboard,
    create_offer_letter, create_completion_certificate, delete_certificate,preview_offer_certificate,delete_offer_certificate,download_offer_certificate
)

urlpatterns = [

    # ======================
    # 🔐 Authentication Routes
    # ======================
    path('login/<str:role>/', login_view, name='login'),                     # Role-based login for admin/coordinator/student
    path('logout/', logout_view, name='logout'),                             # Logout and clear session
    path('dashboard/', dashboard_redirect, name='dashboard_redirect'),      # Redirect to appropriate dashboard based on role

    # ======================
    # 📊 Dashboards
    # ======================
    path('dashboard/admin/', admin_dashboard, name='admin_dashboard'),       # Admin dashboard view
    path('dashboard/coordinator/', coordinator_dashboard, name='coordinator_dashboard'),  # Coordinator dashboard view
    path('dashboard/student/', student_dashboard, name='student_dashboard'), # Student dashboard view

    # ======================
    # 👨‍🎓 Student Management
    # ======================
    path('student/add/', add_student, name='add_student'),                   # Coordinator adds a student

    # ======================
    # 📥 Bulk Certificate Uploads (CSV)
    # ======================
    path('certificate/offer/bulk-upload/', views.bulk_offer_upload, name='bulk_offer_upload'),         # Bulk upload offer letters
    path('certificate/completion/bulk-upload/', views.bulk_completion_upload, name='bulk_completion_upload'), # Bulk upload completion certs

    # ======================
    # 📝 Manual Certificate Creation
    # ======================
    path('certificate/offer/create/', create_offer_letter, name='create_offer_letter'),  
    path('admin/create-template/', views.template_editor, name='create_certificate_template'),
                                                                                                # Create offer letter manually
    path('certificate/completion/create/', create_completion_certificate, name='create_completion_certificate'), # Create completion cert manually

    # ======================
    # 📩 Contact Form
    # ======================
    path('contact/', contact_view, name='contact'),                          # Contact form (email + DB store)

    # ======================
    # ✅ Certificate Verification
    # ======================
    path('verify/', verification_view, name='verify'),                       # Credential verification page

    # ======================
    # 📄 Certificate Download
    # ======================
    path('certificate/download/<int:cert_id>/', download_certificate, name='download_certificate'),  # Student downloads certificate

    # ======================
    # 🔄 Session Ping (for timeout handling)
    # ======================
    path('accounts/ping/', views.ping_session, name='ping_session'),        # AJAX ping to keep session alive

    # ======================
    # 🎨 Certificate Template Management (Admin Only)
    # ======================
    path('admin/create-template/', views.template_editor, name='create_certificate_template'),
      # Template editor UI
    path('admin/template-editor/save/', views.save_template, name='save_template'),                # Save template via POST
    # path('admin/create-template/', views.create_certificate_template, name='create_certificate_template'),  # Admin creates template

    # ======================
    # 🗑️ Certificate Deletion (Admin only)
    # ======================
    path('certificate/<int:cert_id>/delete/', views.delete_certificate, name='delete_certificate'),  # Delete certificate by ID
    path('certificates/offer/<int:pk>/preview/', views.preview_offer_certificate, name='preview_offer_certificate'),
    path('certificates/offer/<int:pk>/download/', views.download_offer_certificate, name='download_offer_certificate'),
    path('certificates/offer/<int:pk>/delete/', views.delete_offer_certificate, name='delete_offer_certificate'),

    # ======================
    # 🗑️ Admin Edit & Deletion (Admin only)
    # ======================
    path('admins/<int:admin_id>/edit/', views.edit_admin, name='edit_admin'),
    path('admins/<int:admin_id>/delete/', views.delete_admin, name='delete_admin'),

    # ======================
    # 🗑️ Coordiator Edit & Deletion (Admin only)
    # ======================
    path('coordinator/edit/<int:pk>/', views.edit_coordinator, name='edit_coordinator'),
    path('coordinator/delete/<int:pk>/', views.delete_coordinator, name='delete_coordinator'),

    # ======================
    # 🗑️ Student Deletion (Admin only)
    # ======================
    path('certificate/delete/<int:pk>/', delete_certificate, name='delete_certificate'),

]
