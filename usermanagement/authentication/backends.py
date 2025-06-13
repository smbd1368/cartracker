from rest_framework import authentication, exceptions
from usermanagement.models import JustPackUser
from core.settings import ALGORITHM
from django.conf import settings
# import logging
import jwt



SECRET_KEY = settings.SECRET_KEY

# logger = logging.getLogger(__name__)

class JWTAuthentication(authentication.BaseAuthentication):
    authentication_header_prefix = 'Bearer'

    def authenticate(self, request):
        
        auth_header = authentication.get_authorization_header(request).split()
        # if len(auth_header)==2:
        #     auth_header= auth_header[1]
        
        auth_header_prefix = self.authentication_header_prefix.lower()
        
        if not auth_header:
            return None

        if len(auth_header) == 1:
            return None

        elif len(auth_header) > 2:
            return None

        prefix = auth_header[0].decode('utf-8')
        token = auth_header[1].decode('utf-8')
        
        if prefix.lower() != auth_header_prefix:
            return None

        return self._authenticate_credentials(request, token)

    def _authenticate_credentials(self, request, token):
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        except Exception as e:
            # logger.warning(f'Authentication failed: {e}')
            raise exceptions.AuthenticationFailed()

        try:
            user = JustPackUser.objects.get(pk=payload['user_id'])            
        except JustPackUser.DoesNotExist:
            # logger.warning(f'User not found for token: {token}')
            raise exceptions.AuthenticationFailed()

                # Check the token version
        if user.token_version != payload.get('token_version'):
            raise exceptions.AuthenticationFailed('Token has been invalidated.')
        
        if not user.is_active:
            # logger.warning(f'Inactive user attempted authentication: {user.username}')
            raise exceptions.AuthenticationFailed()

        # logger.info(f'Successful authentication for user: {user.username}')
        return (user, token)
    def validate_token(self, token):
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        except Exception as e:
            raise exceptions.AuthenticationFailed(f'Invalid token: {e}')
        return payload
    def validate_refresh_token(self, token):
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        except Exception as e:
            raise exceptions.AuthenticationFailed(f'Invalid refresh token: {e}')

        try:
            user = JustPackUser.objects.get(pk=payload['user_id'])
        except JustPackUser.DoesNotExist:
            raise exceptions.AuthenticationFailed('Invalid refresh token')

        return user
