from django.urls import path
from django.shortcuts import redirect
from django.conf import settings
from . import views
from .views import (
    add_student, update_template_setting, student_login_view, verification_view, contact_view, download_certificate,
    login_view, logout_view, dashboard_redirect,
    admin_dashboard, coordinator_dashboard, student_dashboard,
    create_offer_letter, create_completion_certificate, delete_certificate
)

urlpatterns = [

     
    # 🔐 Authentication Routes
     
    path('login/<str:role>/', login_view, name='login'),                     # Role-based login for admin/coordinator/student
    path('logout/', logout_view, name='logout'),                             # Logout and clear session
    path('dashboard/', dashboard_redirect, name='dashboard_redirect'),      # Redirect to appropriate dashboard based on role

     
    # 📊 Dashboards
     
    path('dashboard/admin/', admin_dashboard, name='admin_dashboard'),       # Admin dashboard view
    path('dashboard/coordinator/', coordinator_dashboard, name='coordinator_dashboard'),  # Coordinator dashboard view
    path('dashboard/student/', student_dashboard, name='student_dashboard'), # Student dashboard view

     
    # 👨‍🎓 Student Management
     
    path('student/add/', add_student, name='add_student'),                                                    # Coordinator adds a student

     
    # 📥 Bulk Certificate Uploads (CSV)
     
    path('certificate/offer/bulk-upload/', views.bulk_offer_upload, name='bulk_offer_upload'),                # Bulk upload offer letters
    path('certificate/completion/bulk-upload/', views.bulk_completion_upload, name='bulk_completion_upload'), # Bulk upload completion certs

     
    # 📝 Manual Certificate Creation
     
    path('certificate/offer/create/', create_offer_letter, name='create_offer_letter'),                
    path('certificate/completion/create/', create_completion_certificate, name='create_completion_certificate'), # Create completion cert manually
    
     
    # 📩 Contact Form
     
    path('contact/', contact_view, name='contact'),                          # Contact form (email + DB store)

     
    # ✅ Certificate Verification
     
    path('verify/', verification_view, name='verify'),                       # Credential verification page

     
    # 📄 Certificate Download
     
    path('certificate/download/<int:cert_id>/', download_certificate, name='download_certificate'),  # Student downloads certificate

     
    # 🔄 Session Ping (for timeout handling)
     
    # path('accounts/ping/', views.ping_session, name='ping_session'),        # AJAX ping to keep session alive
    path('ping/', views.ping_session, name='ping_session'),

     
    # 🗑️ Certificate Deletion (Admin only)
     
    path('certificate/<int:cert_id>/delete/', views.delete_certificate, name='delete_certificate'),  # Delete certificate by ID
    path('certificates/offer/<int:pk>/preview/', views.preview_offer_certificate, name='preview_offer_certificate'),
    path('certificates/offer/<int:pk>/download/', views.download_offer_certificate, name='download_offer_certificate'),
    path('certificates/offer/<int:pk>/delete/', views.delete_offer_certificate, name='delete_offer_certificate'),

     
    # 🗑️ Admin Edit & Deletion (Admin only)
     
    path('admins/<int:admin_id>/edit/', views.edit_admin, name='edit_admin'),
    path('admins/<int:admin_id>/delete/', views.delete_admin, name='delete_admin'),

     
    # 🗑️ Coordiator Edit & Deletion (Admin only)
     
    path('coordinator/edit/<int:pk>/', views.edit_coordinator, name='edit_coordinator'),
    path('coordinator/delete/<int:pk>/', views.delete_coordinator, name='delete_coordinator'),
    
    # Certificate Edit page
    path('certificate/edit/<int:pk>/', views.edit_certificate, name='edit_certificate'),
    
    path("certificates/<str:student_id>/", views.certificates_by_student, name="certificates_by_student"),
    
    # Generate completion certificate with offer letter data
    path("certificate/generate-completion/<int:pk>/", views.generate_completion, name="generate_completion"),
   
    # Preview function
    path("certificate/<int:pk>/preview/", views.preview_certificate, name="preview_certificate"),


    path("accounts/certificates/<int:pk>/", views.certificate_detail, name="certificate_detail"),

    
    # 🗑️ Student Deletion (Admin only)
     
    path('certificate/delete/<int:cert_id>/', delete_certificate, name='delete_certificate'),
    
    path('queries/submit/', views.submit_query, name='submit_query'),
    path("queries/list/", views.query_list, name="query_list"),
    path("queries/resolve/<int:pk>/", views.resolve_query, name="resolve_query"),
    path("queries/delete/<int:pk>/", views.delete_query, name="delete_query"),
    
    path("update-template-setting/", views.update_template_setting, name="update_template_setting"),       #save template based on admin choice


]
