C:\\Python310\\python.exe -m venv benv
source benv/Scripts/activate
.\benv\Scripts\activate
C:\Users\bagher\Documents\amini-tracker-car\benv\Scripts\python.exe -m pip install --upgrade pip
pip install -r .\requirements.txt

Get-ChildItem -Path .\*\migrations\*.py -Exclude __init__.py -Recurse | Remove-Item -Force












<!-- 

from .core import *
from pathlib import Path
import os
from decouple import config , Csv
from pathlib import Path
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-5*$c9!sc8jqc7fs29&!5u2c$f@r0eyl%^hv5j#(k)og%6ep@+_'

DEBUG = True
# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True


# ALLOWED_HOSTS = config('ALLOWED_HOSTS', cast=Csv())
ALLOWED_HOSTS = ['*']

ROOT_URLCONF = 'justpack.urls'
print(config('Name'),config('Name'))
Name = config('Name')
User = config('User')
PASSWORD = config('PASSWORD')
HOST = config('HOST')
PORT = config('PORT')

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': Name,
        'USER': User,
        'PASSWORD': PASSWORD,
        'HOST': HOST,
        'PORT': PORT,
        'DISABLE_SERVER_SIDE_CURSORS': True,

    }
}


#                           """"""OTP"""""

OTP_EXPIRATION_MINUTES = 10

SMS_IR_TEMPLATE_ID=100000
SMS_IR_API_KEY='gvf60M2rEvdRC3AhffjfvKMDpKv06V7stQzI2dqGKaU76T0ZvkO0kDVUxIjkgqXL'


REST_FRAMEWORK = {
    'UPLOADED_FILES_USE_URL':True,
    # 'EXCEPTION_HANDLER': 'users.exceptions.responses.core_exception_handler',
    # 'NON_FIELD_ERRORS_KEY': 'error',
    # 'DEFAULT_FILTER_BACKENDS': ['django_filters.rest_framework.DjangoFilterBackend'],
    
    # For all API I can use this authentication
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'usermanagement.authentication.backends.JWTAuthentication',
    ],
    'DEFAULT_PARSER_CLASSES': [
        'rest_framework.parsers.MultiPartParser',
        'rest_framework.parsers.FormParser',
        'rest_framework.parsers.JSONParser',
    ],
}

TIMESTATIC_REDIS = 2592000
TIMETemporaryAPI_REDIS = 86400
TIMEQuickAPI_REDIS = 60
 -->