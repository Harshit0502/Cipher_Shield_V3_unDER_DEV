from rest_framework import serializers
from .models import Message
from django.contrib.auth import get_user_model
from auth_system.models import KeyPair
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

User = get_user_model()

class MessageSerializer(serializers.ModelSerializer):
    sender = serializers.ReadOnlyField(source='sender.username')

    class Meta:
        model = Message
        fields = ['id', 'sender', 'receiver', 'encrypted_text', 'timestamp']

    def create(self, validated_data):
        request = self.context['request']
        sender = request.user
        receiver = validated_data['receiver']
        plain_text = request.data['plain_text']

        # ✅ Step 1: Load receiver's public key
        try:
            keypair = KeyPair.objects.get(user=receiver)
            public_key = serialization.load_pem_public_key(
                keypair.public_key.encode()
            )
        except KeyPair.DoesNotExist:
            raise serializers.ValidationError({'error': 'Receiver public key not found.'})

        # ✅ Step 2: Encrypt the message
        encrypted_message = public_key.encrypt(
            plain_text.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # ✅ Step 3: Fill validated data
        validated_data['sender'] = sender
        validated_data['encrypted_text'] = encrypted_message.hex()  # Store encrypted text as hex

        return super().create(validated_data)

