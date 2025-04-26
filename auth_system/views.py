from django.shortcuts import render
from rest_framework import generics
from .serializers import UserSignupSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.permissions import AllowAny
from rest_framework import permissions
from rest_framework.response import Response
from .models import KeyPair

class UserSignupView(generics.CreateAPIView):
    serializer_class = UserSignupSerializer
    permission_classes = [AllowAny]

class UserLoginView(TokenObtainPairView):
    permission_classes = [AllowAny]

# auth_system/views.py

class PrivateKeyRetrieveView(generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        user = request.user
        try:
            keypair = KeyPair.objects.get(user=user)
            return Response({'private_key': keypair.private_key}, status=200)
        except KeyPair.DoesNotExist:
            return Response({'error': 'KeyPair not found.'}, status=404)
