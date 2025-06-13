from django.core.signing import TimestampSigner, BadSignature
from core.settings import SIGNATURE_MAX_AGE

class SecureSerializationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        return response

    def sign_data(self, data):
        signer = TimestampSigner()
        return signer.sign(data)

    def verify_signature(self, signed_data):
        signer = TimestampSigner()
        try:
            unsigned_data = signer.unsign(signed_data, max_age=SIGNATURE_MAX_AGE)
            return unsigned_data
        except BadSignature:
            return None