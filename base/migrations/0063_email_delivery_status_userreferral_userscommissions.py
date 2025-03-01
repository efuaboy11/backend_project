# Generated by Django 5.1.2 on 2024-12-25 20:54

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0062_remove_withdraw_wallet_address_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='email',
            name='delivery_status',
            field=models.CharField(choices=[('pending', 'Pending'), ('failed', 'Failed'), ('delivered', 'Delivered')], default='pending', max_length=10),
        ),
        migrations.CreateModel(
            name='UserReferral',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('referral_id', models.CharField(blank=True, max_length=16, unique=True)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('referral_user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='referral_user', to=settings.AUTH_USER_MODEL)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='user', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='UsersCommissions',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('transaction_id', models.CharField(blank=True, max_length=16, unique=True)),
                ('amount', models.DecimalField(decimal_places=2, default=0.0, max_digits=10)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
