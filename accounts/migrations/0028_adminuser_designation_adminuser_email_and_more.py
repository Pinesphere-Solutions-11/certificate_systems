# Generated by Django 5.2.2 on 2025-08-01 10:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0027_alter_certificate_qr_code_path'),
    ]

    operations = [
        migrations.AddField(
            model_name='adminuser',
            name='designation',
            field=models.CharField(default='Not Provided', max_length=100),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='adminuser',
            name='email',
            field=models.EmailField(default='Not Provided', max_length=254, unique=True),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='adminuser',
            name='employment_id',
            field=models.CharField(default='PS001', max_length=50, unique=True),
        ),
        migrations.AddField(
            model_name='adminuser',
            name='phone',
            field=models.CharField(blank=True, max_length=15, null=True),
        ),
    ]
