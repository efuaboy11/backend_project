# Generated by Django 5.1.1 on 2024-10-20 10:33

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0035_remove_rawpassword_email_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='rawpassword',
            name='user',
        ),
        migrations.AddField(
            model_name='rawpassword',
            name='email',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='rawpassword',
            name='full_name',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='rawpassword',
            name='user_name',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]
