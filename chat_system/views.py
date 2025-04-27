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
from rest_framework.permissions import IsAuthenticated
import pandas as pd
import joblib
import os

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

class DetectThreatsAPIView(APIView):
    permission_classes = [IsAuthenticated]  # 🔐 Only authenticated users can trigger

    def post(self, request):
        try:
            if not os.path.exists('extended_user_features_5000.csv'):
                return Response({"error": "Features CSV not found."}, status=400)

            df = pd.read_csv('extended_user_features_5000.csv')

            if df.empty:
                return Response({"error": "No user data found."}, status=400)

            usernames = df['username']
            X = df.drop(columns=['username'])

            if not os.path.exists('rf_model.joblib') or not os.path.exists('scaler.joblib'):
                return Response({"error": "Model or scaler not found."}, status=400)

            model = joblib.load('rf_model.joblib')
            scaler = joblib.load('scaler.joblib')
            X_scaled = scaler.transform(X)

            scores = model.predict_proba(X_scaled)[:, 1]

            suspicious_users = []

            for i, score in enumerate(scores):
                threats = []
                user = usernames[i]

                if df.loc[i, 'msgs'] > 100:
                    threats.append('Flooding Detected')
                if df.loc[i, 'rate_limits'] > 5:
                    threats.append('Rate Limit Abuse')
                if df.loc[i, 'fails'] > 10:
                    threats.append('Brute Force Attempt')
                if score > 0.7:
                    threats.append('ML Threat Detected')

                if threats:
                    suspicious_users.append({
                        'username': user,
                        'threats': threats,
                        'ml_score': round(score, 3)
                    })

            if suspicious_users:
                with open('alerts.log', 'w') as alert_file:
                    for user_info in suspicious_users:
                        alert_file.write(f"User: {user_info['username']} | Threats: {', '.join(user_info['threats'])} | ML Score: {user_info['ml_score']}\n")

                return Response({
                    "message": f"{len(suspicious_users)} suspicious users detected.",
                    "alerts_created": True
                }, status=200)

            else:
                return Response({"message": "No suspicious users detected."}, status=200)

        except Exception as e:
            return Response({"error": str(e)}, status=500)
