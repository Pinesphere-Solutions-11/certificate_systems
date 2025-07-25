# Generated by Django 5.2.3 on 2025-06-27 05:19

import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0003_remove_certificate_signature_image_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='certificate',
            name='issue_date',
            field=models.DateField(default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='certificate',
            name='signature',
            field=models.ImageField(blank=True, null=True, upload_to='signatures/'),
        ),
        migrations.AlterField(
            model_name='certificate',
            name='director_name',
            field=models.CharField(max_length=100),
        ),
    ]
