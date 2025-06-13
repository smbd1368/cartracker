from rest_framework import serializers

class VerifySignatureSerializer(serializers.Serializer):
    signed_data = serializers.CharField()