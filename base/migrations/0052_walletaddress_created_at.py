# Generated by Django 5.1.2 on 2024-12-05 11:25

import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0051_alter_userverifiactiondetails_created_at_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='walletaddress',
            name='created_at',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
    ]
