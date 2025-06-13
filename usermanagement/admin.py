from django.contrib import admin
from .models import (
    JustPackUser,
    PaxUser,
    OTPLog,
    AgnUser,
    )

admin.site.register(JustPackUser)
admin.site.register(PaxUser)
admin.site.register(OTPLog)
admin.site.register(AgnUser)
