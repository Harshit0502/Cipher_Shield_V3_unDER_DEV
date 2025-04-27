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

        # ✅ Extract plain_text safely from validated_data
        plain_text = validated_data.pop('plain_text', None)
        if plain_text is None:
            raise serializers.ValidationError({'error': 'Plain text message is required.'})

        # ✅ Load receiver's public key
        try:
            keypair = KeyPair.objects.get(user=receiver)
            public_key = serialization.load_pem_public_key(
                keypair.public_key.encode()
            )
        except KeyPair.DoesNotExist:
            raise serializers.ValidationError({'error': 'Receiver public key not found.'})

        # ✅ Encrypt the plain_text message
        encrypted_message = public_key.encrypt(
            plain_text.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # ✅ Fill required fields
        validated_data['sender'] = sender
        validated_data['encrypted_text'] = encrypted_message.hex()  # Store as hex string

        return super().create(validated_data)
