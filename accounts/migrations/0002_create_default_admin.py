from django.db import migrations

def create_admin_user(apps, schema_editor):
    from django.contrib.auth import get_user_model
    User = get_user_model()

    if not User.objects.filter(username='admin').exists():
        User.objects.create_superuser(
            username='admin',
            email='pinespheresolutions144@gmail.com',
            password='admin123',
            role='admin'
        )
    if not User.objects.filter(username='saran').exists():
        User.objects.create_user(
            username='saran',
            email='coordinator@example.com',
            password='saran123',
            role='coordinator'
        )
    if not User.objects.filter(username='praveen').exists():
        User.objects.create_user(
            username='praveen',
            email='student@example.com',
            password='praveen123',
            role='student'
        )

class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(create_admin_user),
    ]
