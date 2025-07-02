
from django.db import migrations
from django.contrib.auth.hashers import make_password

def create_users(apps, schema_editor):
    User = apps.get_model('accounts', 'User')

    # Admin
    User.objects.create(
        username='admin',
        full_name='Admin User',
        role='admin',
        password=make_password('admin123'),
        is_superuser=True,
        is_staff=True
    )

    # Coordinator
    User.objects.create(
        username='coordinator',
        full_name='Coordinator User',
        role='coordinator',
        password=make_password('coordinator123')
    )

    # Student
    User.objects.create(
        username='student001',
        full_name='Student User',
        role='student',
        password=make_password('student123')
    )

class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0001_initial'),  # or your actual previous migration
    ]

    operations = [
        migrations.RunPython(create_users),
    ]
