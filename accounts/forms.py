from django import forms
from django.contrib.auth.forms import AuthenticationForm
from .models import Coordinator, Student, AdminUser
from django.contrib.auth import get_user_model

User = get_user_model()

class LoginForm(AuthenticationForm):
    username = forms.CharField(widget=forms.TextInput(attrs={
        'class': 'form-control', 'placeholder': 'Enter username'
    }))
    password = forms.CharField(widget=forms.PasswordInput(attrs={
        'class': 'form-control', 'placeholder': 'Enter password'
    }))

class CoordinatorForm(forms.ModelForm):
    class Meta:
        model = Coordinator
        fields = ['full_name', 'email', 'designation', 'employment_id', 'phone']

class StudentForm(forms.ModelForm):
    class Meta:
        model = Student
        fields = ['full_name', 'email', 'student_id', 'department']
        

class AdminUserForm(forms.ModelForm):
    username = forms.CharField(max_length=150)
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = AdminUser
        fields = ['full_name', 'username', 'email', 'password']



# forms.py

from .models import ContactMessage

class ContactMessageForm(forms.ModelForm):
    class Meta:
        model = ContactMessage
        fields = ['name', 'email', 'subject', 'message']