from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
import datetime

class User(AbstractUser):
    ROLE_CHOICES = [
        ('admin', 'Admin'),
        ('coordinator', 'Coordinator'),
        ('student', 'Student'),
    ]
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='student')
    full_name = models.CharField(max_length=100, default='Unknown User')


    def __str__(self):
        return f"{self.full_name} ({self.username}) - {self.role}"

class Coordinator(models.Model):
    full_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    department = models.CharField(max_length=100)
    phone = models.CharField(max_length=15, blank=True)

class Student(models.Model):
    full_name = models.CharField(max_length=100)
    email = models.EmailField()
    student_id = models.CharField(max_length=20, unique=True)
    department = models.CharField(max_length=100)

    def __str__(self):
        return self.full_name

class AdminUser(models.Model):
    full_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=100, unique=True)
    password = models.CharField(max_length=128)


from django.core.files.storage import FileSystemStorage
from django.contrib.auth import get_user_model

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

    # ✅ Add these two:
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    generated_pdf = models.FileField(upload_to='certificates/', blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        # Generate certificate number like PS001
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

class CertificateTemplate(models.Model):
    TEMPLATE_TYPES = (
        ('offer', 'Internship Offer Letter'),
        ('completion', 'Internship Completion Certificate'),
    )

    name = models.CharField(max_length=100)
    type = models.CharField(max_length=20, choices=TEMPLATE_TYPES)
    background_image = models.ImageField(upload_to='certificate_templates/')
    font_family = models.CharField(max_length=100, default='Times New Roman')
    html_content = models.TextField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.get_type_display()})"