from django.shortcuts import get_object_or_404
from rest_framework import generics, permissions
from .models import Message  # or ChatMessage if that's your model
from .serializers import MessageSerializer
from django.contrib.auth.models import User
from django.db.models import Q
from rest_framework.response import Response
from .models import KeyPair  # make sure this model exists
from rest_framework.views import APIView

class PublicKeyRetrieveView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, username):
        try:
            user = User.objects.get(username=username)
            keypair = KeyPair.objects.get(user=user)
            return Response({'public_key': keypair.public_key})
        except User.DoesNotExist:
            return Response({'error': 'User not found.'}, status=404)
        except KeyPair.DoesNotExist:
            return Response({'error': 'Public key not found.'}, status=404)


# 🚀 Send Message View
class SendMessageView(generics.CreateAPIView):
    serializer_class = MessageSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        receiver_username = self.request.data.get('receiver')
        encrypted_text = self.request.data.get('plain_text')

        receiver = get_object_or_404(User, username=receiver_username)

        serializer.save(sender=self.request.user, receiver=receiver, encrypted_text=encrypted_text)

# 🚀 Chat History View
class ChatHistoryView(generics.ListAPIView):
    serializer_class = MessageSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        other_user_username = self.request.query_params.get('with')

        other_user = get_object_or_404(User, username=other_user_username)

        return Message.objects.filter(
            (Q(sender=user, receiver=other_user)) |
            (Q(sender=other_user, receiver=user))
        ).order_by('timestamp')
