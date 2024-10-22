# Generated by Django 5.1.1 on 2024-10-12 06:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0015_userinvestment_created_at'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userinvestment',
            name='investment_status',
            field=models.CharField(choices=[('awaiting', 'Awaiting'), ('active', 'Active'), ('completed', 'Completed')], default='awaiting', max_length=20),
        ),
    ]
