# Generated by Django 5.1.2 on 2024-12-14 06:33

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0061_alter_withdraw_payment_method_type'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='withdraw',
            name='wallet_address',
        ),
        migrations.RemoveField(
            model_name='withdraw',
            name='wallet_name',
        ),
    ]
