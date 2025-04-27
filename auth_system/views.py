from django.shortcuts import render
from rest_framework import generics, permissions
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from .serializers import UserSignupSerializer
from .models import KeyPair

# 🚀 Utility Function
def get_keypair_or_create(user):
    keypair, created = KeyPair.objects.get_or_create(user=user)
    return keypair

# 🚀 User Signup View
class UserSignupView(generics.CreateAPIView):
    serializer_class = UserSignupSerializer
    permission_classes = [AllowAny]
    
    def perform_create(self, serializer):
        user = serializer.save()
        get_keypair_or_create(user)  # Create KeyPair after successful signup

# 🚀 User Login View
class UserLoginView(TokenObtainPairView):
    permission_classes = [AllowAny]
    

# 🚀 Private Key Retrieval View
class PrivateKeyRetrieveView(generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = request.user

        keypair = get_keypair_or_create(user)

        if not keypair.private_key:
            return Response({'error': 'Private key not found.'}, status=404)

        return Response({'private_key': keypair.private_key}, status=200)
