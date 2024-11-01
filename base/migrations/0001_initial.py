# Generated by Django 5.1.1 on 2024-10-09 21:13

import django.db.models.deletion
import django.utils.timezone
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
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
        migrations.CreateModel(
            name='NewUser',
            fields=[
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('email', models.EmailField(max_length=254, unique=True, verbose_name='email address')),
                ('user_name', models.CharField(max_length=100)),
                ('full_name', models.CharField(max_length=100)),
                ('start_date', models.DateField(default=django.utils.timezone.now)),
                ('is_staff', models.BooleanField(default=False)),
                ('is_active', models.BooleanField(default=True)),
                ('role', models.CharField(choices=[('ADMIN', 'Admin'), ('USER', 'User')], default='USER', max_length=50)),
                ('date_joined', models.DateTimeField(default=django.utils.timezone.now)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='KYCverification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('document_type', models.CharField(max_length=50)),
                ('country', models.CharField(max_length=50)),
                ('proof_selfie', models.ImageField(upload_to='kyc/')),
                ('font_side', models.ImageField(upload_to='kyc/')),
                ('back_side', models.ImageField(upload_to='kyc/')),
                ('status', models.CharField(choices=[('verified', 'Verified'), ('unverified', 'Unverified'), ('pending', 'Pending')], default='pending', max_length=10)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='OTPGenerator',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('otp', models.CharField(max_length=6)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Deposit',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('amount', models.DecimalField(decimal_places=2, max_digits=10)),
                ('payment_proof', models.ImageField(upload_to='deposit_proofs/')),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('declined', 'Declined'), ('successful', 'Successful')], default='pending', max_length=10)),
                ('transaction_id', models.CharField(blank=True, max_length=16, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('payment_method', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to='base.paymentmethod')),
            ],
        ),
        migrations.CreateModel(
            name='UserBalance',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('balance', models.DecimalField(decimal_places=2, default=0.0, max_digits=10)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='UserVerifiactionDetails',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('first_name', models.CharField(max_length=20)),
                ('last_name', models.CharField(max_length=20)),
                ('date_of_birth', models.DateField()),
                ('gender', models.CharField(choices=[('male', 'Male'), ('female', 'Female'), ('others', 'Others')], default='male', max_length=10)),
                ('phone_number', models.IntegerField()),
                ('profile_photo', models.ImageField(upload_to='profile_img/')),
                ('address', models.CharField(max_length=50)),
                ('city_town', models.CharField(max_length=50)),
                ('state', models.CharField(max_length=50)),
                ('country', models.CharField(choices=[('argentina', 'Argentina'), ('australia', 'Australia'), ('brazil', 'Brazil'), ('canada', 'Canada'), ('china', 'China'), ('colombia', 'Colombia'), ('egypt', 'Egypt'), ('ethiopia', 'Ethiopia'), ('france', 'France'), ('germany', 'Germany'), ('ghana', 'Ghana'), ('greece', 'Greece'), ('india', 'India'), ('indonesia', 'Indonesia'), ('iran', 'Iran'), ('iraq', 'Iraq'), ('ireland', 'Ireland'), ('israel', 'Israel'), ('italy', 'Italy'), ('ivory_coast', 'Ivory Coast'), ('japan', 'Japan'), ('kenya', 'Kenya'), ('malaysia', 'Malaysia'), ('mexico', 'Mexico'), ('morocco', 'Morocco'), ('nepal', 'Nepal'), ('netherlands', 'Netherlands'), ('new_zealand', 'New Zealand'), ('nigeria', 'Nigeria'), ('norway', 'Norway'), ('pakistan', 'Pakistan'), ('peru', 'Peru'), ('philippines', 'Philippines'), ('poland', 'Poland'), ('portugal', 'Portugal'), ('qatar', 'Qatar'), ('russia', 'Russia'), ('saudi_arabia', 'Saudi Arabia'), ('singapore', 'Singapore'), ('south_africa', 'South Africa'), ('south_korea', 'South Korea'), ('spain', 'Spain'), ('sri_lanka', 'Sri Lanka'), ('sweden', 'Sweden'), ('switzerland', 'Switzerland'), ('thailand', 'Thailand'), ('turkey', 'Turkey'), ('united_kingdom', 'United Kingdom'), ('united_states', 'United States'), ('vietnam', 'Vietnam')], default='argentina', max_length=50)),
                ('zip_code', models.CharField(max_length=20)),
                ('ssn', models.CharField(max_length=30)),
                ('status', models.CharField(choices=[('verified', 'Verified'), ('unverified', 'Unverified'), ('pending', 'Pending')], default='pending', max_length=10)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('referral', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='refferal', to=settings.AUTH_USER_MODEL)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Withdraw',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('amount', models.DecimalField(decimal_places=2, max_digits=10)),
                ('wallet_address', models.CharField(max_length=100)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('declined', 'Declined'), ('successful', 'Successful')], max_length=10)),
                ('transaction_id', models.CharField(blank=True, max_length=16, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
