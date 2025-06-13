# views.py
from rest_framework import generics
from rest_framework.response import Response
from .middlewares import SecureSerializationMiddleware
from .serializers import VerifySignatureSerializer

class VerifySignatureView(generics.GenericAPIView):
    serializer_class = VerifySignatureSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        signed_data = serializer.validated_data['signed_data']
        middleware = SecureSerializationMiddleware(get_response=None)
        
        unsigned_data = middleware.verify_signature(signed_data)
        # unsigned_data is the data that has been successfully verified after checking the signature.
        if unsigned_data:
            return Response({'unsigned_data': unsigned_data})
        else:
            return Response({'error': 'Invalid signature'}, status=400)