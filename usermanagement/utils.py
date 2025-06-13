import requests
import json
from datetime import datetime, timedelta
from django.conf import settings
from .models import OTPLog
import random
import string

def send_otp(mobile):
    # Generate a random 5-digit OTP
    otp = ''.join(random.choices(string.digits, k=5))

    # Check if there's an existing OTP log for the user
    otp_log, created = OTPLog.objects.get_or_create(
        user=mobile,
        defaults={'otp': otp}
    )

    if not created:
        # Update the existing OTP log
        otp_log.otp = otp
        otp_log.save()

    # Prepare the API request payload
    payload = json.dumps({
        "mobile": mobile,
        "templateId": settings.SMS_IR_TEMPLATE_ID,
        "parameters": [
            {
                "name": "Code",
                "value": otp
            }
        ]
    })

    # Set the API headers
    headers = {
        'X-API-KEY': settings.SMS_IR_API_KEY,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    # Send the API request
    response = requests.request("POST", "https://api.sms.ir/v1/send/verify", headers=headers, data=payload)

    # Check if the API request was successful
    if response.status_code == 200:
        return True
    else:
        return False
