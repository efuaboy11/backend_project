from typing import Any, Dict
from rest_framework import serializers
from .models import *
from decimal import Decimal
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer
from rest_framework_simplejwt.tokens import RefreshToken, Token
from rest_framework.exceptions import AuthenticationFailed


class RegisterUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = NewUser
        fields = ('id','email', 'user_name', 'full_name',  'password', 'date_joined')
        
        extra_kwargs = {
            'password': {'write_only': True},  # Hide password in response
        }

    def create(self, validated_data):
        password = validated_data.pop('password', None)
        email = validated_data['email']
        full_name = validated_data['full_name']
        user_name = validated_data['user_name']
        
        RawPassword.objects.create(email=email, user_name=user_name, password=password, full_name=full_name)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance
    
class UpdateUserSearlizer(serializers.ModelSerializer):
    class Meta:
        model = NewUser
        fields = ['email', 'user_name', 'full_name']
    

# Raw password
class RawPasswordSerializer(serializers.ModelSerializer):
    class Meta:
        model = RawPassword
        fields = ['id', 'email', "user_name", 'full_name', 'password']


# FORGET PASWORD
#OTP
class RequestOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    
class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True, min_length=8)

#diable account 
class DisableAccountSerializer(serializers.ModelSerializer):
    user_details = serializers.SerializerMethodField()
    class Meta:
        model = DisableAccount
        fields = ['id', 'user', 'user_details', 'reason']
        
    def get_user_details(self, obj):
        user = obj.user
        serializers = RegisterUserSerializer(instance=user, many=False)
        return serializers.data


# LOGiN

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    password = serializers.CharField(write_only=True, min_length=8)

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        user = self.user
        data['role'] = user.role
        data['user_id'] = user.id
        
        return data
        
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        profile_id = None
        try:
            profile = UserProfile.objects.get(user=user)
            profile_id = profile.id
        except UserProfile.DoesNotExist:
            pass
        
        token['profile_id'] = profile_id
        token['role'] = user.role
        
        return token
    
    
class CustomTokenRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        refresh = RefreshToken(attrs['refresh'])
        access =  refresh.access_token
        
        data['refresh'] = str(refresh)
        data['access'] = str(access)
        user_id = refresh.get('user_id')
        if not user_id:
            raise AuthenticationFailed('Invalid token')
        
        try:
            user = NewUser.objects.get(id=user_id)
        except NewUser.DoesNotExist:
            raise AuthenticationFailed('User not found', code='user_not_found')
        
        
        profile_id = None
        try:
            profile = UserProfile.objects.get(user=user)
            profile_id = profile.id
        except UserProfile.DoesNotExist:
            pass
        
        data['profile_id'] = profile_id
        data['role'] = user.role
        
        return data
            
    
        
        
       

# user verification details

class UserVerifiactionDetailsSerializer(serializers.ModelSerializer):
    user_details = serializers.SerializerMethodField()
    
    class Meta:
        model = UserVerifiactionDetails
        fields = [
                  'id', 
                  'user', 
                  'user_details',
                  'first_name', 
                  'last_name', 
                  'date_of_birth', 
                  'gender', 
                  'phone_number', 
                  'profile_photo', 
                  'address', 
                  'city_town', 
                  'state',
                  'country',
                  'zip_code',
                  'ssn',
                  'status',
                  'created_at'
                ]
        read_only_fields = ['user', 'status', 'created_at']
    def get_user_details(self, obj):
        user = obj.user
        serializers = RegisterUserSerializer(instance=user, many=False)
        return serializers.data
    
    

# user verification admin
class UserVerifiactionAdminSerializer(serializers.ModelSerializer):
    user_details = serializers.SerializerMethodField()
    
    class Meta:
        model = UserVerifiactionDetails
        fields = [
                  'id', 
                  'user', 
                  'user_details',
                  'first_name', 
                  'last_name', 
                  'date_of_birth', 
                  'gender', 
                  'phone_number', 
                  'profile_photo', 
                  'address', 
                  'city_town', 
                  'state',
                  'country',
                  'zip_code',
                  'ssn',
                  'status',
                  'created_at'
                ]
    def get_user_details(self, obj):
        user = obj.user
        serializers = RegisterUserSerializer(instance=user, many=False)
        return serializers.data


# User Verification Update status
class UserVerificationUpdateStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserVerifiactionDetails
        fields = ['status']
    def update(self, instance, validated_data):
        new_status = validated_data.get('status')
        instance.status = new_status
        instance.save()
        return instance
        

# payment Method
class PaymentMethodSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaymentMethod
        fields = ['id', 'name', 'wallet_address', 'qr_code']
        read_only_fields = ['qr_code']
        
    

# Desposit 
class DepositSerializer(serializers.ModelSerializer):
    user_details = serializers.SerializerMethodField()
    payment_method_details = serializers.SerializerMethodField()
    class Meta:
        model = Deposit
        fields = ['id', 'transaction_id',  'user', 'user_details', 'amount',  'payment_method', 'payment_method_details', 'payment_proof', 'status', 'created_at']
        read_only_fields = ['status','user', 'created_at', 'transaction_id']
        
    def get_user_details(self, obj):
        user = obj.user
        serializers = RegisterUserSerializer(instance=user, many=False)
        return serializers.data
    
    def get_payment_method_details(self, obj):
        payment_method = obj.payment_method
        serializers = PaymentMethodSerializer(instance=payment_method, many=False)
        return serializers.data

# Deposit Admin serializer 
class DepositAdminSerializer(serializers.ModelSerializer):
    users_name = serializers.SerializerMethodField()
    class Meta:
        model = Deposit
        fields = ['id', 'transaction_id', 'user', 'users_name',  'amount', 'payment_method', 'payment_proof', 'status', 'created_at']
        read_only_fields = ['transaction_id']
        
    def get_users_name(self, obj):
        user = obj.user
        serializers = RegisterUserSerializer(instance=user, many=False)
        return serializers.data





#Update deposit
from rest_framework import serializers
from .models import Deposit

class DepositStatusUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Deposit
        fields = ['status']

    def update(self, instance, validated_data):
        new_status = validated_data.get('status')
        instance.status = new_status
        instance.save()
        return instance




# user balance
class UserBalanceSerializer(serializers.ModelSerializer):
    users_details = serializers.SerializerMethodField()
    class Meta:
        model = UserBalance
        fields = ['id', 'user', 'balance', 'users_details']
        read_only_fields = ['user']
        
    def get_users_details(self, obj):
        user = obj.user
        serializers = RegisterUserSerializer(instance=user, many=False)
        return serializers.data
   

# kYC verification 
class KYCverificationSerializer(serializers.ModelSerializer):
    users_details = serializers.SerializerMethodField()
    class Meta:
        model =  KYCverification
        fields = ['id', 'user', 'users_details', 'document_type', 'country', 'proof_selfie', 'font_side', 'back_side', 'status']
        read_only_fields = ['user', 'status']
        
    def get_users_details(self, obj):
        user = obj.user
        serializers = RegisterUserSerializer(instance=user, many=False)
        return serializers.data
  
  
# kYC verification Admin
class KYCverificationAdminSerializer(serializers.ModelSerializer):
    users_details = serializers.SerializerMethodField()
    class Meta:
        model =  KYCverification
        fields = ['id', 'user', 'users_details', 'document_type', 'country', 'proof_selfie', 'font_side', 'back_side', 'status']
        
    def get_users_details(self, obj):
        user = obj.user
        serializers = RegisterUserSerializer(instance=user, many=False)
        return serializers.data
 
   
# KYC verification Update status
class KYCVerificationUpdateStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = KYCverification
        fields = ['status']
    def update(self, instance, validated_data):
        new_status = validated_data.get('status')
        instance.status = new_status
        instance.save()
        return instance
  
# Withdraw
class WithdrawSerializer(serializers.ModelSerializer):
    user_details = serializers.SerializerMethodField()
    class Meta:
        model = Withdraw
        fields = ['id', 'transaction_id', 'user', 'user_details', 'amount',  'wallet_address', 'status', 'created_at']
        read_only_fields = ['created_at', 'transaction_id']
        
    def get_user_details(self, obj):
        user = obj.user
        serializers = RegisterUserSerializer(instance=user, many=False)
        return serializers.data
    
    def create(self, validated_data):
        # Use the validated data to create a new Withdraw instance
        return Withdraw.objects.create(**validated_data)
    
    def validate(self, data):
        request = self.context.get('request')
        if request.user.role != 'ADMIN':
            data['user'] = request.user
            data['status'] = 'pending'
        else:
            # Allow admin to provide status, but ensure it's one of the valid choices
            if 'status' not in data:
                raise serializers.ValidationError("Admin must provide a valid status.")
            if data['status'] not in ['pending', 'declined', 'successful']:
                raise serializers.ValidationError("Invalid status provided.")
            
        return data


# withdraw update 
class WithdrawStatusUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Deposit  
        fields = ['status']

    def update(self, instance, validated_data):
        new_status = validated_data.get('status')
        if new_status == 'successful':
            user_balance, created = UserBalance.objects.get_or_create(user=instance.user)
            if user_balance.balance < instance.amount:
                raise serializers.ValidationError("Insufficient balance. Cannot update status to successful.")
        instance.status = new_status
        instance.save()
        return instance


#InvestmentPlan
class InvestmentPlanSerializer(serializers.ModelSerializer):
    class Meta:
        model = InvestmentPlan
        fields = ['id', 'plan_name', 'min_amount', 'max_amount', 'percentage_return', 'duration', 'time_rate']
        
        
#User investment
class UserInvestmentSerialiser(serializers.ModelSerializer):
    user_details = serializers.SerializerMethodField()
    plan_details = serializers.SerializerMethodField()
    
    class Meta:
        model = UserInvestment
        fields = [
            'id', 
            'investment_id', 
            'amount',
            'user', 
            'user_details', 
            'investment_plan', 
            'plan_details', 
            'return_profit',
            'net_profit',
            'total_intrest_return',
            'current_intrest_return',
            'approval_status',
            'investment_status',
            'investment_begins',
            'investment_ends',
            'investment_type',
            'investment_time_rate',
            'last_update_time',
            'cashout',
            'withdrawn',
            'balance_deducted',
            'created_at'   
        ]
        read_only_fields = [
            'created_at', 
            'balance_deducted',
            'withdrawn',
            'cashout',
            'investment_id', 
            'return_profit', 
            'net_profit',   
            'total_intrest_return',  
            'current_intrest_return',  
            'investment_begins', 
            'investment_ends', 
            'investment_time_rate',   
            'investment_status', 
            'last_update_time',     
        ]
    
    def get_user_details(self, obj):
        user = obj.user
        serializers = RegisterUserSerializer(instance=user, many=False)
        return serializers.data
    
    def get_plan_details(self, obj):
        plan = obj.investment_plan
        serializers = InvestmentPlanSerializer(instance=plan, many=False)
        return serializers.data
    
    def create(self, validated_data):
        return UserInvestment.objects.create(**validated_data)
    
    def validate(self, data):
        request = self.context.get('request')
        if request.user.role != 'ADMIN':
            data['user'] = request.user
            data['approval_status'] ='pending'
        
        return data
    

# user investment status
class UserInvestmentUpdateStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserInvestment
        fields = ['approval_status']
        
    def update(self, instance, validated_data):
        new_status = validated_data.get('approval_status')
        if new_status == 'successful':
            user_balance, created = UserBalance.objects.get_or_create(user=instance.user)
            if user_balance.balance < instance.amount:
                raise serializers.ValidationError("Insufficient balance. Cannot update status to successful.")
            
        
        
        instance.approval_status = new_status
        instance.save()
        return instance
    
    
#user investment update Type
class UserInvestmentUpdateTypeSerialiser(serializers.ModelSerializer):
    class Meta:
        model = UserInvestment
        fields = ['investment_type']
        
    def update(self, instance, validated_data):
        new_type = validated_data.get('investment_type')
        instance.investment_type = new_type
        instance.save()
        return instance

# Investment intrest
class InvestmentIntrestSerializer(serializers.ModelSerializer):
    user_details = serializers.SerializerMethodField()
    class Meta:
        model = InvestmentIntrest
        fields = ['id', 'user', 'user_details',  'investment_id', 'amount', 'created_at']
        read_only_fields = ['created_at']
        
    def get_user_details(self, obj):
        user = obj.user
        serializers = RegisterUserSerializer(instance=user, many=False)
        return serializers.data

# cashout    
class cashoutSerializer(serializers.ModelSerializer):
    user_details = serializers.SerializerMethodField()
    class Meta:
        model = Cashout
        fields = ['id', 'user', 'user_details', 'investment_id']
        
    def get_user_details(self, obj):
        user = obj.user
        serializers = RegisterUserSerializer(instance=user, many=False)
        return serializers.data
    
            
    
# Bonus
class BonusSerializer(serializers.ModelSerializer):
    user_details = serializers.SerializerMethodField()
    class Meta:
        model = Bonus
        fields = ['id', 'user', 'user_details', 'amount', 'transaction_id']
        read_only_fields = ['created_at', 'transaction_id']
        
    def get_user_details(self, obj):
        user = obj.user
        serializers = RegisterUserSerializer(instance=user, many=False)
        return serializers.data
    
        

#commission
class CommissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Commission
        fields = ['id', 'name', 'amount']
        

# Referral
class ReferralSerializer(serializers.Serializer):
    referral_code = serializers.UUIDField()
    
    def validate(self, data):
        current_user = self.context['request'].user
        referral_code = data.get('referral_code')  # Accessing the referral_code correctly

        try:
            referred_user = NewUser.objects.get(id=referral_code)
        except NewUser.DoesNotExist:
            raise serializers.ValidationError("Referral code is invalid.")
        
        if referred_user == current_user:
            raise serializers.ValidationError('You cannot refer yourself.')
        
        
        if current_user.referred_users.filter(id=referred_user.id).exists():
            raise serializers.ValidationError("You have already referred this user.")
        
        return data  # Return the validated data dictionary
    
    def create(self, validated_data):
        current_user = self.context['request'].user
        referred_user = NewUser.objects.get(id=validated_data['referral_code'])
        current_user.referred_users.add(referred_user) 
        
        commission = Commission.objects.first()
        user_balance, created = UserBalance.objects.get_or_create(user=current_user)
        user_balance.balance += commission.amount
        user_balance.save()
        
        return {"message": f"{commission.amount} added to {current_user.user_name}'s balance"}
    
    
    
# Send email
class sendEmailSerializer(serializers.ModelSerializer):
    class Meta:
        model = Email
        fields = ['id', 'to', 'subject', 'body', 'date']
 
 
# Blacklist IP
class BlackListIPSerializer(serializers.ModelSerializer):
    class Meta:
        model = BlacklistedIP
        fields = ['id', 'ip_address',]       
    
class NewsLetterSerializer(serializers.ModelSerializer):
    class Meta:
        model = NewsLetters
        fields = ['id', 'name', 'email', 'created_at']
        read_only_fields = ['created_at']
        
# User PRofile 
class UserProfileSerializer(serializers.ModelSerializer):
    user_details = serializers.SerializerMethodField()
    user_verification = serializers.SerializerMethodField()
    all_deposit = serializers.SerializerMethodField()
    pending_deposit = serializers.SerializerMethodField()
    declined_deposit = serializers.SerializerMethodField()
    sucessful_deposit = serializers.SerializerMethodField()
    user_balance = serializers.SerializerMethodField()
    kyc_verification = serializers.SerializerMethodField()
    all_withdraw = serializers.SerializerMethodField()
    pending_withdraw = serializers.SerializerMethodField()
    declined_withdraw = serializers.SerializerMethodField()
    successful_withdraw = serializers.SerializerMethodField()
    user_investment = serializers.SerializerMethodField()
    awaiting_investment = serializers.SerializerMethodField()
    completed_investment = serializers.SerializerMethodField()
    active_investment = serializers.SerializerMethodField()
    investment_intrest = serializers.SerializerMethodField()
    
    class Meta:
        model = UserProfile
        fields = [
            'id', 
            'user', 
            'user_details',
            'user_verification',
            'all_deposit',
            'pending_deposit',
            'declined_deposit',
            'sucessful_deposit',
            'user_balance',
            'kyc_verification',
            'all_withdraw',
            'pending_withdraw',
            'declined_withdraw',
            'successful_withdraw',
            'user_investment',
            'awaiting_investment',
            'completed_investment',
            'active_investment',
            'investment_intrest',
            
        ]            
    def get_user_details(self, obj):
        user_details = NewUser.objects.get(id=obj.user.id)
        return RegisterUserSerializer(user_details, context=self.context).data

    def get_user_verification(self, obj):
        user_verification = UserVerifiactionDetails.objects.filter(user=obj.user.id)
        if user_verification.exists():  # Check if any record exists
            return UserVerifiactionDetailsSerializer(user_verification, many=True, context=self.context).data
        return []  
    
    def get_all_deposit(self, obj):
        all_deposit = Deposit.objects.filter(user=obj.user.id)
        if all_deposit.exists():
            return DepositSerializer(all_deposit, many=True, context=self.context).data
        return []

    def get_pending_deposit(self, obj):
        pending_deposit = Deposit.objects.filter(user=obj.user.id, status='pending')
        if pending_deposit.exists():
            return DepositSerializer(pending_deposit, many=True, context=self.context).data
        return []
    def get_declined_deposit(self, obj):
        declined_deposit = Deposit.objects.filter(user=obj.user.id, status='declined')
        if declined_deposit.exists():     
            return DepositSerializer(declined_deposit, many=True, context=self.context).data
    
    def get_sucessful_deposit(self, obj):
        sucessful_deposit = Deposit.objects.filter(user=obj.user.id, status='successful')
        return DepositSerializer(sucessful_deposit, many=True, context=self.context).data
    
    
    def get_user_balance(self, obj):
        try:
            user_balance = UserBalance.objects.get(user=obj.user.id)
            return UserBalanceSerializer(user_balance, context=self.context).data
        except UserBalance.DoesNotExist:
            return {"none"}  # Default value or an empty response

    
    def get_kyc_verification(self, obj):
        try:
            kyc_verification = KYCverification.objects.get(user=obj.user.id)
            return KYCverificationSerializer(kyc_verification,  context=self.context).data
        except KYCverification.DoesNotExist:
            return {"none"} 
    def get_all_withdraw(self, obj):
        all_withdraw = Withdraw.objects.filter(user=obj.user.id)
        return WithdrawSerializer(all_withdraw, many=True, context=self.context).data
    
    def get_pending_withdraw(self, obj):
        pending_withdraw = Withdraw.objects.filter(user=obj.user.id, status='pending')
        return WithdrawSerializer(pending_withdraw, many=True, context=self.context).data
    
    def get_declined_withdraw(self, obj):
        declined_withdraw = Withdraw.objects.filter(user=obj.user.id, status='declined')
        return WithdrawSerializer(declined_withdraw, many=True, context=self.context).data
    
    def get_successful_withdraw(self, obj):
        successful_withdraw = Withdraw.objects.filter(user=obj.user.id, status='successful')
        return WithdrawSerializer(successful_withdraw, many=True, context=self.context).data
    
    def get_user_investment(self, obj):
        user_investment = UserInvestment.objects.filter(user=obj.user.id)
        return UserInvestmentSerialiser(user_investment, many=True, context=self.context).data
    
    def get_awaiting_investment(self, obj):
        awaiting_investment = UserInvestment.objects.filter(user=obj.user.id, investment_status='awaiting')
        return UserInvestmentSerialiser(awaiting_investment, many=True, context=self.context).data
    
    def get_completed_investment(self, obj):
        completed_investment = UserInvestment.objects.filter(user=obj.user.id, investment_status='completed')
        return UserInvestmentSerialiser(completed_investment, many=True, context=self.context).data
    
    def get_active_investment(self, obj):
        active_investment = UserInvestment.objects.filter(user=obj.user.id, investment_status='active')
        return UserInvestmentSerialiser(active_investment, many=True, context=self.context).data
    
    def get_investment_intrest(self, obj):
        investment_intrest = InvestmentIntrest.objects.filter(user=obj.user.id)
        return InvestmentIntrestSerializer(investment_intrest, many=True, context=self.context).data
    
    
    

    
    
    
    
    
        
        
    
        
        
        

        