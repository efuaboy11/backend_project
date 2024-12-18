# Generated by Django 5.1.2 on 2024-12-04 21:21

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0050_newuser_profile_photo'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userverifiactiondetails',
            name='created_at',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
        migrations.CreateModel(
            name='WalletAddress',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('label', models.CharField(max_length=100)),
                ('walletAddress', models.CharField(max_length=100)),
                ('coin', models.CharField(choices=[('bitcoin', 'Bitcoin'), ('ethereum', 'Ethereum'), ('tether', 'Tether'), ('litecoin', 'Litecoin'), ('ripple', 'Ripple'), ('cardano', 'Cardano'), ('dogecoin', 'Dogecoin'), ('stellar', 'Stellar')], max_length=100)),
                ('network', models.CharField(choices=[('BEP2', 'BEP2'), ('BEP20', 'BEP20'), ('ERC20', 'ERC20'), ('OMNI', 'OMNI'), ('TRC20', 'TRC20')], max_length=100)),
                ('transaction_id', models.CharField(blank=True, max_length=16, unique=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
