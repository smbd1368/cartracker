from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
from django.core.signing import TimestampSigner
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.http import Http404
from django.conf import settings

from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema

from rest_framework.generics import CreateAPIView, UpdateAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import generics, status
from rest_framework.views import APIView

from usermanagement.authentication.backends import JWTAuthentication
from usermanagement.permissions import IsAuthenticate, IsPaxPermission
from .swagger_schemas import get_change_cell_number_swagger, get_change_password_swagger, get_change_username_with_token_swagger, get_pax_user_image_update_swagger
from usermanagement.utils import send_otp

from .models import AgnUser, JustPackUser, OTPLog, PaxUser
from .serializers import AgnUserSerializer, ChangeUsernameSerializer, LoginSerializer, LoginTokenSerializer, JustPackUserLanguageSerializer, PasswordChangeSerializer, PasswordChangeWithTokenSerializer, PasswordChangewithOTpSerializer, PaxUserChangePasswordSerializer, PaxUserImageSerializer, \
     PaxUserReteriveRetrieveSerializer, \
    PaxUserSerializer, PaxUserUpdateSerializer, RefreshTokenSerializer, TokenSerializer
from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from drf_yasg.utils import swagger_auto_schema

class AgnUserListView(generics.ListAPIView):
    """
        This API view allows you to retrieve the list of users with the "Agn" (Agency) type.

    When a GET request is made to this endpoint, the view performs the following steps:
    1. It retrieves all the `JustPackUser` instances with the `type` field set to "Agn". 🔍
    2. It serializes the retrieved users using the `JustPackUserSerializer`. 🗄️
    3. It returns the serialized user data in the response. 📤
    """
    serializer_class = AgnUserSerializer
    
    def get_queryset(self):
        return AgnUser.objects.filter(marked_as_associate=True)

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context['include_related_data'] = True
        context['response'] = getattr(self, 'response', None)   
    
        return context
    
    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)
        signed_data = self.get_signed_data(response)
        if signed_data:
            response['HTTP_X_Signed_Data'] = signed_data
        return response

    def get_signed_data(self, response):
        signed_datanew = ""
        for data in response.data:
            if 'id' in data:
                signed_datanew = signed_datanew+ str(data['id'])
            if 'land_line' in data:
                signed_datanew = signed_datanew+ str(data['land_line'])

            return TimestampSigner().sign(signed_datanew)
        else:
            return None

class UserLoginAPIView(APIView):
    """
    🔑 User Login API Endpoint

    This view handles user login functionality. Here's how it works:

    1. The user enters their cell number and receives an OTP (One-Time Password). 📱✨
    2. The user verifies the OTP by providing the mobile number and OTP in the request. 🔒
    3. If the OTP is valid and the user is verified, the API generates a Bearer token. 🔑
    4. The generated token can be used to authenticate the user in subsequent requests. 🔐
    5. To verify the token, make a GET request to the `/verify-token/` endpoint, passing the token in the Authorization header. 🔗


    """ 
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'username': openapi.Schema(type=openapi.TYPE_STRING),
                'password': openapi.Schema(type=openapi.TYPE_STRING),
            },
        ),
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="Successful response",
                schema=LoginSerializer,
            ),
            status.HTTP_400_BAD_REQUEST: openapi.Response(
                description="Invalid credentials",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
            status.HTTP_404_NOT_FOUND: openapi.Response(
                description="User does not exist",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
            status.HTTP_401_UNAUTHORIZED: openapi.Response(
                description="Invalid credentials",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
            status.HTTP_403_FORBIDDEN: openapi.Response(
                description="User is not verified",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
        },
    )
    def post(self, request):
        user = {
            "username": request.data.get('username'),
            "password": request.data.get('password')
        }
        
        try:
            serializer = self.serializer_class(data=user)
            serializer.is_valid(raise_exception=True)
            
                
            # Check if the user is verified
            if not PaxUser.objects.filter(username = request.data.get('username'),is_verified=True).exists():
                return Response( {"user": ["User is not verified."]}, status=status.HTTP_403_FORBIDDEN)
            
            return Response(serializer.data, status=status.HTTP_200_OK)
               
        except ValidationError:
            return Response({'error': 'Invalid username or password.'}, status=status.HTTP_400_BAD_REQUEST)

        except Http404:
            return Response(
                {"user": ["User does not exist."]}
                , status=status.HTTP_404_NOT_FOUND)
   
class VerifyTokenAPIView(APIView):
    """
    ✅ Verify Token API View

    This API view allows clients to verify the validity of a JWT (JSON Web Token) and check whether the associated user is verified. 🔑

    The view uses the `JWTAuthentication` class for token authentication. Clients must include the JWT token in the `Authorization` header of the request, with the prefix `Bearer `. 🔒

    When a GET request is made to this endpoint, the view performs the following steps:
    1. It extracts the user associated with the provided JWT token. 🔍
    2. It checks the `is_verified` attribute of the user. ✔️
    3. It returns a JSON response with the `is_verified` field set to the appropriate value. 📤 
    """
    
    authentication_classes = [JWTAuthentication]
    serializer_class = TokenSerializer

    @swagger_auto_schema(
        request_body=None,
        responses={200: 'Success'},
        security=[{'Bearer': []}],
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="Bearer token",
                type=openapi.TYPE_STRING,
                required=True
            )
        ]
    )
    def get(self, request):
        try:
            user = request.user
            
            is_verified = user.is_verified  # Assuming 'is_verified' is an attribute of the user model
            
            return Response({'is_verified': is_verified})
        except:
            # If the requested resource is not found
            return Response({'error': 'Resource not found.'}, status=status.HTTP_404_NOT_FOUND)
    
class RefreshTokenAPIView(APIView):
    permission_classes = [AllowAny]
    serializer_class = RefreshTokenSerializer

    @swagger_auto_schema(
        request_body=RefreshTokenSerializer,
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="Successful response",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'token': openapi.Schema(type=openapi.TYPE_STRING),
                        'refresh_token': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
            status.HTTP_401_UNAUTHORIZED: openapi.Response(
                description="Invalid refresh token",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
        },
    )
    def post(self, request):
        try:
            serializer = self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            user = JustPackUser.objects.get(id=JWTAuthentication().validate_refresh_token(serializer.validated_data['refresh_token']).id)
            refresh_token = user.token['refresh_token']
            return Response({'token': user.token['token'], 'refresh_token': refresh_token}, status=status.HTTP_200_OK)        
        except JustPackUser.DoesNotExist:
            return Response({'error': 'Invalid refresh token.'}, status=status.HTTP_401_UNAUTHORIZED)
    
class PaxUserRegisterView(CreateAPIView, UpdateAPIView):
    
    """
    Sign up and verify user
    
    two api in this /pax/ api 
    1. put: verify token for user and 
    2. post: register user
    
    """
    queryset = PaxUser.objects.all()
    
    lookup_field = 'cell_number'
    def get_serializer_class(self):
        # Use PaxUserUpdateSerializer if the request is a PATCH request, otherwise use PaxUserSerializer
        if self.request.method == 'PUT':
            return PaxUserUpdateSerializer
        return PaxUserSerializer

    def create(self, request):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            if not user.is_verified:
                send_otp(user.cell_number)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def update(self, request, *args, **kwargs):
        serializer = PaxUserUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        cell_number = serializer.validated_data['new_cell_number']
        otp = serializer.validated_data['otp']

        try:
            otp_log = OTPLog.objects.get(user=cell_number, otp=otp)
            if otp_log.expires_at < timezone.now():
                return Response({'error': 'OTP has expired'}, status=status.HTTP_400_BAD_REQUEST)
        except OTPLog.DoesNotExist:
            return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

        instance = self.get_object()
        instance.is_verified = True
        self.perform_update(instance)
        return Response({'message': 'User verified successfully'}, status=status.HTTP_200_OK)

    def get_object(self):
        queryset = self.filter_queryset(self.get_queryset())
        cell_number = self.request.data.get('cell_number')
        obj = get_object_or_404(queryset, cell_number=cell_number)
        self.check_object_permissions(self.request, obj)
        return obj

class PaxUserReteriveView(APIView):
    """
    🔍 Pax User Retrieve API View

    This API view allows authorized users and permission to retrieve the details of a Pax user.
    """
    
    serializer_class = PaxUserReteriveRetrieveSerializer
    permission_classes = [IsPaxPermission, ]
    # IsPaxUserManager

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                name='Authorization',
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                description='Bearer token for authentication',
                default='Bearer YOUR_TOKEN',
            )
        ],
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="Successful response",
                schema=PaxUserReteriveRetrieveSerializer,
            ),
            status.HTTP_404_NOT_FOUND: openapi.Response(
                description="User does not exist",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
            status.HTTP_401_UNAUTHORIZED: openapi.Response(
                description="Invalid credentials",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
        }
    )
    def get(self, request, format=None):
        # try:
        pax_user = PaxUser.objects.get(id=request.user.id)
        serializer = self.serializer_class(pax_user, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)
    # except Exception as e:
    #     return Response({'error': str(e)}, status=status.HTTP_404_NOT_FOUND)

class PaxUserImageUpdateAPIView(generics.UpdateAPIView):
    permission_classes = [IsPaxPermission]  
    serializer_class = PaxUserImageSerializer
    queryset = PaxUser.objects.all()  # Queryset for the PaxUser model

    def get_object(self):
        return self.request.user.paxuser  # Adjust this if the relationship is different

    @swagger_auto_schema(**get_pax_user_image_update_swagger())  # Use the schema function
    def put(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    def patch(self, request, *args, **kwargs):
        return self.partial_update(request, *args, **kwargs)
    
    
class SendOTPView(APIView):
    """
    
    📱 Just Send OTP API View

    This API view allows users to request an OTP (One-Time Password) to be sent to their mobile number.

    When a POST request is made to this endpoint, the view performs the following steps:
    1. It extracts the `mobile` number from the request data. 📤
    2. If the `mobile` number is not provided, it returns a 400 Bad Request response with an error message. 🚫
    3. It calls the `send_otp` function, passing the `mobile` number as an argument. 📱✨
    4. If the `send_otp` function is successful, it returns a 200 OK response with a success message. 👍
    5. If the `send_otp` function fails, it returns a 500 Internal Server Error response with an error message. 🚨


    - Note 🔔 - After this point, you can verify the OTP code with a PUT request to the `/pax/` API. 📝 and verify User
    

    Frontend Developers: 💻
        - Use this API to request an OTP when the user needs to verify their mobile number. 📱
        - Check mobile number Validation. 💬
        - Display the appropriate success or error messages to the user based on the API response. 💬
        - Implement a timer or countdown to indicate the OTP expiration time. ⏱️ Also I implemented it in Backend and default is 5 minutes.   

    """
    
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'mobile': openapi.Schema(type=openapi.TYPE_STRING, description='Mobile number'),
            }
        ),
        responses={
            '200': openapi.Response(description='OTP sent successfully'),
            '400': openapi.Response(description='Mobile number is required'),
            '500': openapi.Response(description='Failed to send OTP'),
        }
    )
    def post(self, request):
        mobile = request.data.get('mobile')
        if not mobile:
            return Response({'error': 'Mobile number is required'}, status=status.HTTP_400_BAD_REQUEST)

        if send_otp(mobile):
            return Response({'message': 'OTP sent successfully','time':settings.OTP_EXPIRATION_MINUTES}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Failed to send OTP'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class OTPLogAPIView(APIView):
    """
    📱 Just Send OTP

    This API view allows users to request an OTP (One-Time Password) to be sent to their mobile number.
    
    Then you can verify for this mobile with request Put `/pax/`
    """
    
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'mobile': openapi.Schema(type=openapi.TYPE_STRING, description='Mobile number'),
            }
        ),
        responses={
            '200': openapi.Response(description='OTP sent successfully'),
            '400': openapi.Response(description='Mobile number is required'),
            '500': openapi.Response(description='Failed to send OTP'),
        }
    )
    def post(self, request):
        mobile = request.data.get('mobile')
        if not mobile:
            return Response({'error': 'Mobile number is required'}, status=status.HTTP_400_BAD_REQUEST)

        if send_otp(mobile):
            return Response({'message': 'OTP sent successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Failed to send OTP'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


User = get_user_model()  # Assuming JustPackUser is your custom user model

class PasswordChangeWithOTPView(APIView):
    """
    Change password using OTP verification.
    """
    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                name='Authorization',
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                description='Bearer token for authentication',
                default='Bearer YOUR_TOKEN',
            )
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'new_password': openapi.Schema(type=openapi.TYPE_STRING),
                'otp': openapi.Schema(type=openapi.TYPE_STRING),
            },
        ),
        responses={
            '200': openapi.Response(
                description='Password changed successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
            '400': openapi.Response(
                description='Bad request',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'new_password': openapi.Schema(type=openapi.TYPE_STRING),                        
                        'otp': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
        },
    )
    def post(self, request):
        username = request.user.username  # Get the username from the authenticated user
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response({'username': 'User does not exist.'}, status=status.HTTP_404_NOT_FOUND)

        # Validate input data
        serializer = PasswordChangewithOTpSerializer(data=request.data, context={'request': request, 'user': user})
        
        if serializer.is_valid():
            # Call save method on the user instance directly
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class ChangeUsernameAPIView(generics.UpdateAPIView):
    permission_classes = [IsPaxPermission]  
    serializer_class = PaxUserChangePasswordSerializer
    queryset = PaxUser.objects.all()
    
    """
    User Change Username API Endpoint
    """

    @swagger_auto_schema(**get_change_username_with_token_swagger())  # Use the schema defined above
    def put(self, request, *args, **kwargs):
        # Get the user instance from the request.user
        user = request.user

        # Validate input data
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        new_user_name = serializer.validated_data['new_user_name']
        password = serializer.validated_data['password']

        # Check if the new username is already taken
        if JustPackUser.objects.filter(username=new_user_name).exists():
            print(new_user_name,"taken")
            return Response({'error': 'Username is taken'}, status=status.HTTP_400_BAD_REQUEST)

        # Verify password
        user_auth = authenticate(username=user.username, password=password)
        if user_auth is None:
            return Response({'error': 'Password is incorrect'}, status=status.HTTP_400_BAD_REQUEST)

        # Update username
        user.username = new_user_name
        
        # Increment the token version to invalidate old tokens (if applicable)
        user.token_version += 1  
        
        user.save()

        return Response({'message': 'Username changed successfully.'}, status=status.HTTP_200_OK)
    
class ChangePasswordWithTokenAPIView(generics.UpdateAPIView):
    permission_classes = [IsPaxPermission]
    serializer_class = PasswordChangeWithTokenSerializer

    @swagger_auto_schema(**get_change_password_swagger())
    def put(self, request, *args, **kwargs):
        user = self.request.user
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        # Change the password
        user.set_password(serializer.validated_data['new_password'])
        user.save()

        # Increment the token version to invalidate old tokens
        user.token_version += 1
        user.save()

        # Generate new tokens
        new_tokens = user.token  # This will call the _generate_jwt_token method

        return Response({
            'message': 'Password changed successfully.',
            'token': new_tokens['token'],
            'refresh_token': new_tokens['refresh_token']
        }, status=status.HTTP_200_OK)
        

class ChangeLanguageJustPackUserAPIView(generics.UpdateAPIView):
    queryset = JustPackUser.objects.all()
    serializer_class = JustPackUserLanguageSerializer
    permission_classes = [IsAuthenticate]

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                name='Authorization',
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                description='Bearer token for authentication',
                required=True,
                default='Bearer YOUR_TOKEN',
            )
        ],
        request_body=JustPackUserLanguageSerializer,
        responses={
            status.HTTP_200_OK: openapi.Response(
                description='Language updated successfully',
                schema=JustPackUserLanguageSerializer,
            ),
            status.HTTP_400_BAD_REQUEST: openapi.Response(
                description='Bad request',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
            status.HTTP_404_NOT_FOUND: openapi.Response(
                description='User not found',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
        },
    )
    def put(self, request, *args, **kwargs):
        user = request.user 
        
        serializer = self.get_serializer(user, data=request.data)
        
        if serializer.is_valid():
            serializer.save()  # Save the updated language
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


class PaxUserLocationAPIView(generics.ListAPIView):
    """
    📍 Retrieve Locations for Pax User

    This API view allows authorized users to retrieve their associated locations.
    """
    
    permission_classes = [IsPaxPermission]
    
    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                name='Authorization',
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                description='Bearer token for authentication',
                default='Bearer YOUR_TOKEN',
            )
        ],
        responses={
            status.HTTP_200_OK: openapi.Response(
                description="Successful response with locations",
                schema=openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                            'title_farsi': openapi.Schema(type=openapi.TYPE_STRING),
                            'title_latin': openapi.Schema(type=openapi.TYPE_STRING),
                        },
                    ),
                ),
            ),
            status.HTTP_404_NOT_FOUND: openapi.Response(
                description="User does not exist",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
            status.HTTP_401_UNAUTHORIZED: openapi.Response(
                description="Invalid credentials",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
        }
    )
    
    def get(self, request, *args, **kwargs):
 
        pax_user = PaxUser.objects.get(id=request.user.id)
        
        # Get associated locations
        locations = pax_user.preferred_locations.all()
        
        # Prepare the response data
        response_data = [
            {
                'id': location.id,
                'title_farsi': location.title_farsi,
                'title_latin': location.title_latin,
            }
            for location in locations
        ]
        
        return Response(response_data, status=status.HTTP_200_OK)