from django.shortcuts import render
from rest_framework import generics
from .serializers import UserSignupSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.permissions import AllowAny

class UserSignupView(generics.CreateAPIView):
    serializer_class = UserSignupSerializer
    permission_classes = [AllowAny]

class UserLoginView(TokenObtainPairView):
    permission_classes = [AllowAny]
