# Generated by Django 5.1.2 on 2024-11-21 01:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0049_newuser_status'),
    ]

    operations = [
        migrations.AddField(
            model_name='newuser',
            name='profile_photo',
            field=models.ImageField(blank=True, null=True, upload_to='profile_img/'),
        ),
    ]