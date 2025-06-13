from usermanagement.authentication.backends import JWTAuthentication
from .models import JustPackUser, AgnUser, OTPLog, PaxUser
from django.contrib.auth.password_validation import validate_password
from rest_framework import authentication, exceptions
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate
from datetime import datetime, timedelta
from rest_framework import serializers
from django.utils import timezone
import jwt
from .models import JustPackUser

    
class JustPackUserNameSerializer(serializers.ModelSerializer):
    class Meta:
        model = JustPackUser
        fields = ['first_name', 'last_name']
    
class AgnUserSerializer(serializers.ModelSerializer):
    
    ads_requests = serializers.SerializerMethodField()
    # sign_data = serializers.SerializerMethodField()
    

    class Meta:
        model = AgnUser
        fields = ['id',  'land_line', 'instagram_id', 'address',  'website','ads_requests']
    
    
class JustPackUserLocationSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = JustPackUser
        fields = ['province_id',]
    
class AgnUserNameSerializer(serializers.ModelSerializer):
 
    class Meta:
        model = AgnUser
        fields = ['first_name_farsi', 'last_name_farsi', ]

class TokenSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=1000)
    is_verified = serializers.BooleanField()

    def validate(self, data):
        try:
            user = JustPackUser.objects.get(id=JWTAuthentication().validate_token(data['token'])['user_id'])
            is_verified = user.is_verified
            data['is_verified'] = is_verified
            JWTAuthentication().validate_token(data['token'])
        except (JustPackUser.DoesNotExist, exceptions.AuthenticationFailed):
            raise serializers.ValidationError('Invalid token')
        return data

class RefreshTokenSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(max_length=1000) 
    def validate(self, data):
        try:
            user = JustPackUser.objects.get(id=JWTAuthentication().validate_refresh_token(data['refresh_token']).id)
            # is_verified = user.is_verified
            # data['is_verified'] = is_verified
        except (JustPackUser.DoesNotExist, exceptions.AuthenticationFailed,jwt.DecodeError):
            raise serializers.ValidationError('Invalid refresh token')
        return data
            
class LoginSerializer(serializers.Serializer):
    # id = serializers.CharField(max_length=255, read_only=True)
    # is_verified = serializers.CharField(max_length=255, read_only=True)
    # display_name = serializers.CharField(max_length=255, read_only=True)
    # avatar = serializers.CharField(max_length=255, read_only=True)
    role = serializers.CharField(max_length=20, read_only=True)
    # bio = serializers.CharField(read_only=True)
    # phone = serializers.CharField(max_length=255, read_only=True)
    # email = serializers.CharField(max_length=255)
    username = serializers.CharField(max_length=255, write_only=True)
    password = serializers.CharField(max_length=128, write_only=True)
    # auth = serializers.CharField(max_length=1000, read_only=True)
    token = serializers.CharField(max_length=1000, read_only=True)
    refresh_token = serializers.CharField(max_length=1000, read_only=True)

    def validate(self, data):
        # The `validate` method is where we make sure that the current
        # instance of `LoginSerializer` has "valid". In the case of logging a
        # user in, this means validating that they've provided an email
        # and password and that this combination matches one of the users in
        # our database.
        username = data.get('username', None)
        password = data.get('password', None)

        # Raise an exception if an
        # email is not provided.
        
        if username is None:
            raise serializers.ValidationError(
                'An user_name address is required to log in.'
            )

        # Raise an exception if a
        # password is not provided.
        if password is None:
            raise serializers.ValidationError(
                'A pass-word is required to log in.'
            )

        # The `authenticate` method is provided by Django and handles checking
        # for a user that matches this email/password combination. Notice how
        # we pass `email` as the `username` value since in our User
        # model we set `USERNAME_FIELD` as `email`.
        user = authenticate(username=username, password=password)
   

        # If no user was found matching this email/password combination then
        # `authenticate` will return `None`. Raise an exception in this case.
        if user is None:
            raise serializers.ValidationError(
                'A user not found.'
            )

        # Django provides a flag on our `User` model called `is_active`. The
        # purpose of this flag is to tell us whether the user has been banned
        # or deactivated. This will almost never be the case, but
        # it is worth checking. Raise an exception in this case.
        if not user.is_active:
            raise serializers.ValidationError(
                'This user has been deactivated.'
            )

        # The `validate` method should return a dictionary of validated data.
        # This is the data that is passed to the `create` and `update` methods
        # that we will see later on.
        return {
             
                # 'id': user.id,
                # 'username': user.email,
                # 'is_verified': user.is_verified,
                # 'display_name': user.display_name,
                # 'avatar': user.avatar, 
                'role': user.type,
                # 'bio': user.bio,
                # 'phone': user.phone,
                # 'email': user.email,
                'token':user.token['token'],
                'refresh_token':user.token['refresh_token'],
        }

class PaxUserUpdateSerializer(serializers.ModelSerializer):
    new_cell_number = serializers.CharField(required=True)
    otp = serializers.CharField(required=True)

    class Meta:
        model = PaxUser
        fields = ['new_cell_number', 'otp']

class PaxUserChangePasswordSerializer(serializers.ModelSerializer):
    new_user_name = serializers.CharField(required=True)
    password = serializers.CharField(required=True)

    class Meta:
        model = PaxUser
        fields = ['new_user_name', 'password']
        
class PaxUserSerializer(serializers.ModelSerializer):
    username = serializers.CharField(read_only=True)
    class Meta:
        model = PaxUser
        fields = ['cell_number', 'password', 'type','username']
        default = {'type': 'Pax'}

    def validate_cell_number(self, value):
        if not value.isnumeric():
            raise serializers.ValidationError('Cell number must be numeric')
        return value

    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError('Password must be at least 8 characters')
        return value

    def validate_type(self, value):
        if value != 'Pax':
            raise serializers.ValidationError('Type must be Pax')
        return value

    def validate(self, data):
        cell_number = data.get('cell_number')
        if PaxUser.objects.filter(cell_number=cell_number).exists():
            raise serializers.ValidationError('User already exists')
        data['username'] = cell_number
        return data

    def create(self, validated_data):
        # Hash the password using the Django password hashing scenario
        validated_data['password'] = make_password(validated_data['password'])
        return super().create(validated_data)

    def to_representation(self, instance):
        # Remove the password field from the response
        data = super().to_representation(instance)
        del data['password']
        return data

    
class PaxUserReteriveRetrieveSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaxUser
        fields = [
            'id',
            'email',
            'first_name',
            'last_name',
            'cell_number',
            
            'date_joined',
            'last_login',   

            ]

class SendOTPSerializer(serializers.Serializer):
    mobile = serializers.CharField(max_length=15)


class PasswordChangewithOTpSerializer(serializers.Serializer):
    new_password = serializers.CharField(required=True)
    otp = serializers.CharField(required=True)

    def validate(self, data):
        user = self.context['user']  # Use the user passed in context

        # Validate new password complexity
        try:
            validate_password(data['new_password'], user=user)
        except Exception as e:
            raise serializers.ValidationError({'new_password': str(e)})

        # Validate OTP
        otp = data['otp']
        otp_logs = OTPLog.objects.filter(user=user, otp=otp)

        if not otp_logs.exists():
            raise serializers.ValidationError({'otp': 'Invalid or expired OTP.'})

        # Check if the latest OTP is valid
        latest_otp_log = otp_logs.latest('created_at')  # Assuming you have a timestamp field like created_at
        if not latest_otp_log.is_valid():  # Assuming is_valid() checks if the OTP is still valid based on its expiration
            raise serializers.ValidationError({'otp': 'Invalid or expired OTP.'})

        return data
           
class PasswordChangeSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    
    new_password = serializers.CharField(required=True)
    confirm_password = serializers.CharField(required=True)
    otp = serializers.CharField(required=True)

    def validate(self, data):
        user = JustPackUser.objects.get(username=data['username'])

        # # Validate old password
        # if not user.check_password(data['old_password']):
        #     raise serializers.ValidationError({'old_password': 'Incorrect old password.'})

        # Validate new password and confirm password
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({'confirm_password': 'New password and confirm password do not match.'})

        # Validate new password complexity
        try:
            validate_password(data['new_password'], user=user)
        except Exception as e:
            raise serializers.ValidationError({'new_password': str(e)})

        # Validate OTP
        try:
            otp_log = OTPLog.objects.get(user=user.cell_number, otp=data['otp'])
            if not otp_log.is_valid():
                raise serializers.ValidationError({'otp': 'Invalid or expired OTP.'})
        except OTPLog.DoesNotExist:
            raise serializers.ValidationError({'otp': 'Invalid or expired OTP.'})

        return data

    def save(self, **kwargs):
        user = JustPackUser.objects.get(username=self.validated_data['username'])
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user

class PaxUserImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaxUser
        fields = '__all__' 

class ChangeUsernameSerializer(serializers.ModelSerializer):
    new_username = serializers.CharField(required=True)

    class Meta:
        model = PaxUser
        fields = ['new_username']

    def validate_new_username(self, value):
        # Check if the new username is already taken
        if PaxUser.objects.filter(username=value).exists():
            raise serializers.ValidationError("This username is already taken.")
        return value

    def update(self, instance, validated_data):
        # Update the username
        instance.username = validated_data['new_username']
        instance.save()
        return instance

class PaxUserProvinceSerializer(serializers.ModelSerializer):
    class Meta:
        model = PaxUser
        fields = ['province_id'] 
    
class PasswordChangeWithTokenSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    confirm_password = serializers.CharField(required=True)

    def validate(self, data):
        user = self.context['request'].user

        # Validate old password
        if not user.check_password(data['old_password']):
            raise serializers.ValidationError({'old_password': 'Incorrect old password.'})

        # Validate new password and confirm password
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({'confirm_password': 'New password and confirm password do not match.'})

        # Validate new password complexity
        validate_password(data['new_password'], user=user)

        return data
    
class RefreshTokenSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(max_length=1000) 
    def validate(self, data):
        try:
            user = PaxUser.objects.get(id=JWTAuthentication().validate_refresh_token(data['refresh_token']).id)
        except (PaxUser.DoesNotExist, exceptions.AuthenticationFailed, jwt.DecodeError):
            raise serializers.ValidationError('Invalid refresh token')
        return data
    
class LoginTokenSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=255, write_only=True)
    password = serializers.CharField(max_length=128, write_only=True)
    token = serializers.CharField(read_only=True)
    refresh_token = serializers.CharField(read_only=True)

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')

        if username is None:
            raise serializers.ValidationError('A username is required to log in.')

        if password is None:
            raise serializers.ValidationError('A password is required to log in.')

        user = authenticate(username=username, password=password)

        if user is None:
            raise serializers.ValidationError('A user with this username and password was not found.')

        if not user.is_active:
            raise serializers.ValidationError('This user has been deactivated.')

        return {
            'token': str(RefreshToken.for_user(user).access_token),
            'refresh_token': str(RefreshToken.for_user(user)),
        }

    def create_tokens(self, user):
        """
        Create tokens for the user.
        """
        refresh = RefreshToken.for_user(user)
        return {
            'token': str(refresh.access_token),
            'refresh_token': str(refresh),
        }

class JustPackUserLanguageSerializer(serializers.ModelSerializer):
    class Meta:
        model = JustPackUser
        fields = '__all__' 