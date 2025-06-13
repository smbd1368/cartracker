from drf_yasg import openapi
from rest_framework import status
from .serializers import PaxUserImageSerializer

def pax_user_image_update_schema():
    return openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'profile_image': openapi.Schema(
                type=openapi.TYPE_FILE,
                description='Profile image file to upload',
            ),
        },
        required=['profile_image'],  # Make this field required
    )

def get_pax_user_image_update_swagger():
    return {
        'manual_parameters': [
            openapi.Parameter(
                name='Authorization',
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                description='Bearer token for authentication',
                required=True,
                default='Bearer YOUR_TOKEN',
            ),
        ],
        'request_body': pax_user_image_update_schema(),
        'responses': {
            status.HTTP_200_OK: openapi.Response(
                description="Profile image updated successfully",
                schema=PaxUserImageSerializer,
            ),
            status.HTTP_400_BAD_REQUEST: openapi.Response(
                description="Invalid input",
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
        },
        'operation_description': "Update profile image for the authenticated user",
        'security': [{'Bearer': []}],
    }

def get_authorization_parameter():
    return openapi.Parameter(
        name='Authorization',
        in_=openapi.IN_HEADER,
        type=openapi.TYPE_STRING,
        description='Bearer token for authentication',
        default='Bearer YOUR_TOKEN',
    )

def get_authorization_responses():
    return {
        status.HTTP_200_OK: openapi.Response(
            description="Successful response",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                },
            ),
        ),
        status.HTTP_404_NOT_FOUND: openapi.Response(
            description="Resource not found",
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

def change_username_schema():
    return openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'new_username': openapi.Schema(
                type=openapi.TYPE_STRING,
                description='New username to be set',
            ),
        },
        required=['new_username'],  # Make this field required
    )

def get_change_username_swagger():
    return {
        'manual_parameters': [
            openapi.Parameter(
                name='Authorization',
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                description='Bearer token for authentication',
                required=True,
                default='Bearer YOUR_TOKEN',
            ),
        ],
        'request_body': change_username_schema(),
        'responses': {
            status.HTTP_200_OK: openapi.Response(
                description="Username changed successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
            status.HTTP_400_BAD_REQUEST: openapi.Response(
                description="Invalid input",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
            status.HTTP_401_UNAUTHORIZED: openapi.Response(
                description="Unauthorized",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
        },
        'operation_description': "Change the username for the authenticated user",
    }

def pax_user_province_update_schema():
    return openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'province_id': openapi.Schema(
                type=openapi.TYPE_INTEGER,
                description='ID of the province to update',
            ),
        },
        required=['province_id'],  # Make this field required
    )

def get_change_password_swagger():
    return {
        'manual_parameters': [
            openapi.Parameter(
                name='Authorization',
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                description='Bearer token for authentication',
                required=True,
                default='Bearer YOUR_TOKEN',
            ),
        ],
        'request_body': openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'old_password': openapi.Schema(type=openapi.TYPE_STRING, description='Old Password'),
                'new_password': openapi.Schema(type=openapi.TYPE_STRING, description='New Password'),
                'confirm_password': openapi.Schema(type=openapi.TYPE_STRING, description='Confirm New Password'),
            },
            required=['old_password', 'new_password', 'confirm_password'],
        ),
        'responses': {
            status.HTTP_200_OK: openapi.Response(
                description="Password changed successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'token': openapi.Schema(type=openapi.TYPE_STRING),
                        'refresh_token': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
            status.HTTP_400_BAD_REQUEST: openapi.Response(
                description="Invalid input",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
            status.HTTP_401_UNAUTHORIZED: openapi.Response(
                description="Unauthorized",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
            status.HTTP_403_FORBIDDEN: openapi.Response(
                description="Forbidden",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'detail': openapi.Schema(type=openapi.TYPE_STRING, description='Token has been invalidated.'),
                    },
                ),
            ),
        },
        'operation_description': "Change the password for the authenticated user and return new tokens",
        'security': [{'Bearer': []}],
    }

def get_change_cell_number_swagger():
    return {
        'manual_parameters': [
            openapi.Parameter(
                name='Authorization',
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                description='Bearer token for authentication',
                required=True,
                default='Bearer YOUR_TOKEN',
            ),
        ],
        'request_body': openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'new_cell_number': openapi.Schema(type=openapi.TYPE_STRING, description='New Cell Number'),
                'otp': openapi.Schema(type=openapi.TYPE_STRING, description='One-Time Password (OTP) for verification'),
            },
            required=['new_cell_number', 'otp'],
        ),
        'responses': {
            status.HTTP_200_OK: openapi.Response(
                description="Cell number changed successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
            status.HTTP_400_BAD_REQUEST: openapi.Response(
                description="Invalid input or cell number already exists",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
            status.HTTP_403_FORBIDDEN: openapi.Response(
                description="Invalid OTP or OTP has expired",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
        },
        'operation_description': "Change the cell number for the authenticated user after verifying with OTP",
        'security': [{'Bearer': []}],
    }

def get_change_username_with_token_swagger():
    return {
        'manual_parameters': [
            openapi.Parameter(
                name='Authorization',
                in_=openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                description='Bearer token for authentication',
                required=True,
                default='Bearer YOUR_TOKEN',
            ),
        ],
        'request_body': openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'new_user_name': openapi.Schema(type=openapi.TYPE_STRING, description='New Username'),
                'password': openapi.Schema(type=openapi.TYPE_STRING, description='Current Password for verification'),
            },
            required=['new_user_name', 'password'],
        ),
        'responses': {
            status.HTTP_200_OK: openapi.Response(
                description="Username changed successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
            status.HTTP_400_BAD_REQUEST: openapi.Response(
                description="Invalid input or username already exists",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
            status.HTTP_403_FORBIDDEN: openapi.Response(
                description="Password is incorrect",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
        },
        'operation_description': "Change the username for the authenticated user after verifying with the current password",
        'security': [{'Bearer': []}],
    }
