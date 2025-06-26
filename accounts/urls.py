from django.urls import path
from .views import (
    login_view, logout_view, dashboard_redirect,
    admin_dashboard, coordinator_dashboard, student_dashboard,
    create_offer_letter, create_completion_certificate
)

urlpatterns = [
    path('login/<str:role>/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('dashboard/', dashboard_redirect, name='dashboard_redirect'),
    path('dashboard/admin/', admin_dashboard, name='admin_dashboard'),
    path('dashboard/coordinator/', coordinator_dashboard, name='coordinator_dashboard'),
    path('dashboard/student/', student_dashboard, name='student_dashboard'),
    
    # ✅ Certificate creation endpoints
    path('certificate/offer/create/', create_offer_letter, name='create_offer_letter'),
    path('certificate/completion/create/', create_completion_certificate, name='create_completion_certificate'),
]
