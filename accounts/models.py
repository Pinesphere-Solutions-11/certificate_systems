import uuid
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.conf import settings
import qrcode
from io import BytesIO
from django.core.files import File
import random
import string

class User(AbstractUser):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('coordinator', 'Coordinator'),
        ('student', 'Student'),
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    # other fields like email, username, etc. inherited from AbstractUser

    def __str__(self):
        return f"{self.username} ({self.role})"



class Coordinator(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    full_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    designation = models.CharField(max_length=100)
    employment_id = models.CharField(max_length=50, unique=True, default="TEMP123")  # Add default here
    phone = models.CharField(max_length=10, blank=True, null=True)

    def __str__(self):
        return self.user.username

class Student(models.Model):
    full_name = models.CharField(max_length=100)
    email = models.EmailField()
    student_id = models.CharField(max_length=20, unique=True)
    department = models.CharField(max_length=100)

    def __str__(self):
        return self.full_name


class AdminUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, null=True)
    full_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True, blank=True, null=True)
    designation = models.CharField(max_length=100)
    employment_id = models.CharField(max_length=50, unique=True, default="PS001") 
    phone = models.CharField(max_length=10, blank=True, null=True)


    def __str__(self):
        return self.full_name
    
from django.contrib.auth import get_user_model
import json

User = get_user_model()

class Certificate(models.Model):
    CERTIFICATE_TYPES = [
        ('offer', 'Internship Offer Letter'),
        ('completion', 'Internship Completion Certificate'),
    ]

    certificate_type = models.CharField(max_length=20, choices=CERTIFICATE_TYPES)
    certificate_number = models.CharField(max_length=10, unique=True, blank=True)

    title = models.CharField(max_length=10)
    student_name = models.CharField(max_length=100)
    student_id = models.CharField(max_length=30)
    degree = models.CharField(max_length=50, blank=True, null=True)
    department = models.CharField(max_length=100)
    college = models.CharField(max_length=200)
    location = models.CharField(max_length=200)
    course_name = models.CharField(max_length=100)
    start_date = models.DateField()
    end_date = models.DateField()
    duration = models.CharField(max_length=50)
    completion_date = models.DateField()
    director_name = models.CharField(max_length=100)
    issue_date = models.DateField(null=False, blank=False)
    signature = models.ImageField(upload_to='signatures/', null=True, blank=True)
    credential_id = models.CharField(max_length=64, blank=True, editable=False)
    qr_code_path = models.ImageField(upload_to='qr_codes/', max_length=255, blank=True, null=True)
    
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    generated_pdf = models.FileField(upload_to='certificates/', blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.certificate_number:
            last = Certificate.objects.order_by('-id').first()
            if last and last.certificate_number:
                try:
                    num = int(last.certificate_number.replace('PS', '')) + 1
                except ValueError:
                    num = 1
            else:
                num = 1
            self.certificate_number = f"PS{num:03d}"

        # ✅ Generate 16-char credential ID (PS + 14 random mixed-case alphanumeric)
        if not self.credential_id:
            prefix = "PS"
            chars = string.ascii_letters + string.digits   # A-Z + a-z + 0-9
            random_part = ''.join(random.choices(chars, k=14))
            self.credential_id = prefix + random_part   # Example: "PSa9KX7LmN2Q8rT"

        # --- Build QR verification URL ---
        verify_url = f"http://127.0.0.1:8000/verify/?id={self.credential_id}"

        qr = qrcode.QRCode(box_size=6, border=2)
        qr.add_data(verify_url)   # ✅ direct verification link
        qr.make(fit=True)
        img = qr.make_image(fill='black', back_color='white')

        buffer = BytesIO()
        img.save(buffer, format='PNG')
        self.qr_code_path.save(f"{self.certificate_number}_qr.png", File(buffer), save=False)


        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.certificate_type.title()} - {self.certificate_number} - {self.student_name}"
    

class ContactMessage(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    subject = models.CharField(max_length=255)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} - {self.subject}"

# models.py
class CertificateTemplate(models.Model):
    TEMPLATE_TYPES = [
        ('offer', 'Internship Offer Letter'),
        ('completion', 'Internship Completion Certificate'),
    ]
    template_type = models.CharField(max_length=20, choices=TEMPLATE_TYPES, unique=True)
    background_image = models.ImageField(upload_to='certificate_backgrounds/', blank=True, null=True)
    html_content = models.TextField()  # This stores your full HTML with placeholders
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.get_template_type_display()} Template"
    

class StudentQuery(models.Model):
    student_id = models.CharField(max_length=50)   # from session
    student_name = models.CharField(max_length=255)
    subject = models.CharField(max_length=255)
    query = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    resolved = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.student_name} - {self.subject}"
