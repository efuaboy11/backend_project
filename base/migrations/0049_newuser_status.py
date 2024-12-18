# Generated by Django 5.1.2 on 2024-11-20 19:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0048_kycverification_created_at'),
    ]

    operations = [
        migrations.AddField(
            model_name='newuser',
            name='status',
            field=models.CharField(choices=[('verified', 'Verified'), ('canceled', 'Canceled'), ('pending', 'Pending')], default='pending', max_length=10),
        ),
    ]