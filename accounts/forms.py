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
        model = User
        fields = ['full_name', 'email', 'username', 'password']
        widgets = {
            'password': forms.PasswordInput()
        }

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password'])
        user.role = 'coordinator'
        if commit:
            user.save()
        return user


class StudentForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['full_name', 'email', 'username', 'password']
        widgets = {
            'password': forms.PasswordInput()
        }

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password'])
        user.role = 'student'
        if commit:
            user.save()
        return user


class AdminUserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['full_name', 'email', 'username', 'password']
        widgets = {
            'password': forms.PasswordInput()
        }

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password'])
        user.role = 'admin'
        if commit:
            user.save()
        return user
