from django.shortcuts import get_object_or_404
from rest_framework import generics, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from django.db.models import Q
from django.contrib.auth import get_user_model
from auth_system.models import KeyPair
from .models import Message
from .serializers import MessageSerializer

User = get_user_model()

# 🚀 Utility Functions
def get_receiver_or_error(receiver_username):
    try:
        receiver = User.objects.get(username=receiver_username)
        return receiver, None
    except User.DoesNotExist:
        return None, Response({'error': 'User not found.'}, status=404)

def validate_public_key(receiver):
    try:
        keypair = KeyPair.objects.get(user=receiver)
        if not keypair.public_key:
            return Response({'error': 'Public key not found.'}, status=404)
    except KeyPair.DoesNotExist:
        return Response({'error': 'Public key not found.'}, status=404)
    return None

# 🚀 Public Key Retrieval View
class PublicKeyRetrieveView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, username):
        receiver, error = get_receiver_or_error(username)
        if error:
            return error

        error = validate_public_key(receiver)
        if error:
            return error

        keypair = KeyPair.objects.get(user=receiver)
        return Response({'public_key': keypair.public_key})

# 🚀 Send Message View
class SendMessageView(generics.CreateAPIView):
    serializer_class = MessageSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        receiver_username = self.request.data.get('receiver')
        plain_text = self.request.data.get('plain_text')

        receiver, error = get_receiver_or_error(receiver_username)
        if error:
            raise Exception(error.data['error'])  # If you prefer crash. Else, better to modify to return error Response properly.

        error = validate_public_key(receiver)
        if error:
            raise Exception(error.data['error'])

        serializer.save(sender=self.request.user, receiver=receiver, plain_text=plain_text)

# 🚀 Chat History View
class ChatHistoryView(generics.ListAPIView):
    serializer_class = MessageSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        other_user_username = self.request.query_params.get('with')

        other_user, error = get_receiver_or_error(other_user_username)
        if error:
            raise Exception(error.data['error'])  # Same - optionally can modify to return Response

        return Message.objects.filter(
            (Q(sender=user, receiver=other_user)) |
            (Q(sender=other_user, receiver=user))
        ).order_by('timestamp')
