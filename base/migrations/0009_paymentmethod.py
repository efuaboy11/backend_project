# Generated by Django 5.1.1 on 2024-10-09 19:19

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0008_withdraw'),
    ]

    operations = [
        migrations.CreateModel(
            name='PaymentMethod',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('wallet_address', models.CharField(max_length=255, unique=True)),
                ('qr_code', models.ImageField(blank=True, null=True, upload_to='wallet_qr_codes/')),
            ],
        ),
    ]
