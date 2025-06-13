from django.db import models
from core.utils import generate_string_representation
from core.settings import (ALGORITHM, REFRESH_TOKEN_EXPIRATION_SECONDS,
    TOKEN_EXPIRATION_SECONDS)
from django.contrib.auth.models import AbstractUser
from django.db.models.signals import pre_save
from datetime import datetime, timedelta
from django.dispatch import receiver
from django.utils import timezone
from django.conf import settings
from datetime import datetime
from datetime import date
import jdatetime 
import secrets
import uuid
import jwt

# authg login user:
SECRET_KEY = getattr(settings, 'SECRET_KEY', None)

class JustPackUser(AbstractUser):
    USER_TYPES = (
        ('Agn', 'Agn'),
        ('Pax', 'Pax'),
        ('SuperAdmin', 'Super Admin'),
        ('AdminStaff', 'Admin Staff'),
    )

    STATUS_CHOICES = (
        ('Active', 'Active'),
        ('Warned', 'Warned'),
        ('Limited', 'Limited'),
        ('Suspended', 'Suspended'),
        ('Deactivated', 'Deactivated'),
    )

    first_name_farsi = models.CharField(max_length=100, null=True, blank=True)
    last_name_farsi = models.CharField(max_length=100, null=True, blank=True)

    type = models.CharField(max_length=20, choices=USER_TYPES, null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, null=True, blank=True)
    limit_activity_until = models.DateTimeField(null=True, blank=True)
    creation_date = models.DateTimeField(auto_now_add=True)
    email = models.EmailField(null=True, blank=True)
    nid = models.CharField(max_length=16, null=True, blank=True)    
    iban_number = models.CharField(max_length=24, null=True, blank=True)
    dc_number = models.CharField(max_length=16, null=True, blank=True)
    bank = models.IntegerField(null=True, blank=True)
    cell_number = models.CharField(max_length=11, null=True, blank=True)
    emergency_number = models.CharField(max_length=10, null=True, blank=True)
    whatsapp_number = models.CharField(max_length=10, null=True, blank=True)
    telegram_number = models.CharField(max_length=10, null=True, blank=True)
    instagram_id = models.CharField(max_length=100, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_verified = models.BooleanField(default=False)
    token_version = models.IntegerField(default=0)
    class Meta:
        verbose_name = 'All User'
        
    @property
    def token(self):
        """
        Allows us to get a user's token by calling `user.token` instead of
        `user.generate_jwt_token()`.
        """
        return self._generate_jwt_token()

    def _generate_jwt_token(self):
        """
        Generates a JSON Web Token that stores this user's ID and has an expiry
        date set to 30 minutes into the future.
        """
        dt = datetime.now() + timedelta(seconds=TOKEN_EXPIRATION_SECONDS)
        exp_timestamp = int(dt.timestamp())
        
        payload = {
            "user_id": str(self.pk),
            "username": self.username,
            "roles": self.type,
            "timestamp": datetime.utcnow().isoformat(),
            "expiration_time": dt.isoformat(),
            "issued_at": datetime.utcnow().isoformat(),
            "nonce": str(uuid.uuid4()),
            "session_id": str(uuid.uuid4()),
            "exp": exp_timestamp,
            "jti": secrets.token_hex(16),
            "token_version": self.token_version
        }
        
        token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

        
        # Generate refresh token
        refresh_dt = datetime.now() + timedelta(seconds=REFRESH_TOKEN_EXPIRATION_SECONDS)
        refresh_exp_timestamp = int(refresh_dt.timestamp())
        
        refresh_payload = {
            "user_id": str(self.pk),
            "exp": refresh_exp_timestamp,
            "jti": secrets.token_hex(16),
            "token_version": self.token_version 
        }
        
        refresh_token = jwt.encode(refresh_payload, SECRET_KEY, algorithm=ALGORITHM)
        
        return { "token": token,
        "refresh_token": refresh_token
                }
    
class AgnUser(JustPackUser):
    title = models.CharField(max_length=200, blank=True, null=True)
    office_id = models.CharField(max_length=200, blank=True, null=True)    
    address = models.CharField(max_length=300, blank=True, null=True)
    website = models.CharField(max_length=300, blank=True, null=True)

    legal_name = models.CharField(max_length=200, blank=True, null=True)
    manager_name = models.CharField(max_length=50, null=True, blank=True)
    manager_cell = models.CharField(max_length=50, null=True, blank=True)
    manager_email = models.CharField(max_length=50, null=True, blank=True)
    manager_image = models.ImageField(upload_to='manager_images/', null=True, blank=True)
    manager_id = models.CharField(max_length=50, blank=True, null=True)

    land_line = models.CharField(max_length=300, blank=True, null=True)
    whatsapp = models.CharField(max_length=300, blank=True, null=True)
    telegram = models.CharField(max_length=300, blank=True, null=True)

    # Branch/counter details
    counter_name = models.CharField(max_length=300, blank=True, null=True)

    # Images
    logo_img = models.ImageField(upload_to='agent_logos/', blank=True, null=True)
    lcn_a_img = models.ImageField(upload_to='agent_licenses/', blank=True, null=True)
    lcn_b_img = models.ImageField(upload_to='agent_licenses/', blank=True, null=True)
    lcn_j_img = models.ImageField(upload_to='agent_licenses/', blank=True, null=True)
    lcn_p_img = models.ImageField(upload_to='agent_licenses/', blank=True, null=True)
    lcn_number = models.CharField(max_length=300, blank=True, null=True)
    lcn_expires = models.DateField(blank=True, null=True)  
    user_acceptance_to_publish_data = models.BooleanField(default=False)
    guarantee_file = models.FileField(upload_to='guarantee_files/', blank=True, null=True)
    # Financial details
    iban = models.CharField(max_length=24, blank=True, null=True)
    card_no = models.CharField(max_length=16, blank=True, null=True)
    approval = models.BooleanField(default=False)
    note = models.TextField(max_length=1000, blank=True, null=True)

    class Meta:
        verbose_name = 'Agn User'
    def __str__(self):
        return generate_string_representation(self)
    
class PaxUser(JustPackUser):
    id_image = models.ImageField(upload_to='id_pax_user_image/', null=True, blank=True)    
    username_id = models.CharField(max_length=24, null=True, blank=True)    
    passport_image = models.ImageField(upload_to='passport_images/', null=True, blank=True)
    passport_number = models.CharField(max_length=24, null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    date_of_birth = models.DateTimeField(null=True, blank=True)
    emergency_contact_name = models.CharField(max_length=300, null=True, blank=True)
    emergency_contact_number = models.CharField(max_length=300, null=True, blank=True)
    is_head = models.BooleanField(default=False)
    place_of_birth = models.CharField(max_length=300, null=True, blank=True)
    solar_date_of_birth = models.CharField(max_length=300, null=True, blank=True)
    day = models.PositiveSmallIntegerField(null=True, blank=True)
    year = models.PositiveSmallIntegerField(null=True, blank=True)
    father_name = models.CharField(max_length=300, null=True, blank=True)
    
    class Meta:
        verbose_name = 'PAX User'



class OTPLog(models.Model):
    user = models.CharField(max_length=100)
    otp = models.CharField(max_length=5, )
    created_at = models.DateTimeField()
    expires_at = models.DateTimeField(null=True, blank=True)
    
    def save(self, *args, **kwargs):
        self.created_at = timezone.now()
        self.expires_at = self.created_at + timedelta(minutes=settings.OTP_EXPIRATION_MINUTES)
        super().save(*args, **kwargs)

    def is_valid(self):
        return self.expires_at > timezone.now()


