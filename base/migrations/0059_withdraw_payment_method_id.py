# Generated by Django 5.1.2 on 2024-12-12 05:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0058_withdraw_payment_method_type'),
    ]

    operations = [
        migrations.AddField(
            model_name='withdraw',
            name='payment_method_id',
            field=models.PositiveIntegerField(null=True),
        ),
    ]
