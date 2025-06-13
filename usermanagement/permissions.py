from rest_framework.permissions import BasePermission
from .models import (JustPackUser, PaxUser)

class IsPaxPermission(BasePermission):
    message = 'Only Pax can access this page'

    def has_permission(self, request, view):
        
        if request.user.is_authenticated:
            qs = PaxUser.objects.filter(id=request.user.id, is_verified=True)                        
            return qs.exists() and request.user.type == 'Pax'
        else:
            return False


class IsAuthenticate(BasePermission):
    message = 'Only justpackuser can access this page'

    def has_permission(self, request, view):     

        if request.user.is_authenticated:
            qs = JustPackUser.objects.filter(id=request.user.id, is_verified=True)                        
            return qs.exists()
        else:
            return False
        