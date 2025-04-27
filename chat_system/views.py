from django.shortcuts import get_object_or_404
from rest_framework import permissions, generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.db.models import Q
from django.contrib.auth import get_user_model
from auth_system.models import KeyPair
from .models import Message
from .serializers import MessageSerializer
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

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

# 🚀 Send Message View (Fully Correct)
class SendMessageView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        sender = request.user
        receiver_username = request.data.get('receiver')
        plain_text = request.data.get('plain_text')

        if not receiver_username or not plain_text:
            return Response({'error': 'receiver and plain_text are required.'}, status=status.HTTP_400_BAD_REQUEST)

        receiver, error = get_receiver_or_error(receiver_username)
        if error:
            return error

        # Encrypt the plain_text
        try:
            keypair = KeyPair.objects.get(user=receiver)
            public_key = serialization.load_pem_public_key(keypair.public_key.encode())
            encrypted_message = public_key.encrypt(
                plain_text.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except KeyPair.DoesNotExist:
            return Response({'error': 'Receiver public key not found.'}, status=status.HTTP_404_NOT_FOUND)

        # Save the message manually
        message = Message.objects.create(
            sender=sender,
            receiver=receiver,
            encrypted_text=encrypted_message.hex()
        )

        serializer = MessageSerializer(message)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

# 🚀 Chat History View
class ChatHistoryView(generics.ListAPIView):
    serializer_class = MessageSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        other_user_username = self.request.query_params.get('with')

        other_user, error = get_receiver_or_error(other_user_username)
        if error:
            return Message.objects.none()  # Return empty queryset if error

        return Message.objects.filter(
            (Q(sender=user, receiver=other_user)) |
            (Q(sender=other_user, receiver=user))
        ).order_by('timestamp')
