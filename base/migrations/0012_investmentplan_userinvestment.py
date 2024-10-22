# Generated by Django 5.1.1 on 2024-10-11 21:44

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0011_alter_userverifiactiondetails_country_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='InvestmentPlan',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('plan_name', models.CharField(max_length=100)),
                ('min_amount', models.DecimalField(decimal_places=2, max_digits=10)),
                ('max_amount', models.DecimalField(decimal_places=2, max_digits=10)),
                ('percentage_return', models.DecimalField(decimal_places=2, max_digits=5)),
                ('duration', models.CharField(max_length=100)),
                ('time_rate', models.CharField(choices=[('none', 'None'), ('hourly', 'Hourly'), ('daily', 'Daily'), ('weekly', 'Weekly'), ('monthly', 'Monthly'), ('yearly', 'Yearly')], default='none', max_length=10)),
            ],
        ),
        migrations.CreateModel(
            name='UserInvestment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('amount', models.DecimalField(decimal_places=2, max_digits=10)),
                ('investment_id', models.CharField(blank=True, max_length=16, unique=True)),
                ('return_profit', models.DecimalField(decimal_places=2, max_digits=10)),
                ('net_profit', models.DecimalField(decimal_places=2, max_digits=10)),
                ('total_intrest_return', models.DecimalField(decimal_places=2, max_digits=10)),
                ('current_intrest_return', models.DecimalField(decimal_places=2, max_digits=10)),
                ('approval_status', models.CharField(choices=[('pending', 'Pending'), ('declined', 'Declined'), ('successful', 'Successful')], default='pending', max_length=10)),
                ('investment_status', models.CharField(choices=[('awaiting', 'Awaiting'), ('active', 'Active'), ('completed', 'Completed')], default='awaitng', max_length=20)),
                ('investment_begins', models.DateTimeField(blank=True, null=True)),
                ('investment_ends', models.DateTimeField(blank=True, null=True)),
                ('investment_type', models.CharField(choices=[('manual', 'Manual'), ('automatic', 'Automatic')], default='manual', max_length=10)),
                ('investment_time_rate', models.CharField(max_length=10)),
                ('Investment_paln', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='base.investmentplan')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]