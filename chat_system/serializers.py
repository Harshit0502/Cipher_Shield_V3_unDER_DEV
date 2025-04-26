from rest_framework import serializers
from .models import Message
from auth_system.models import CustomUser
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

class MessageSerializer(serializers.ModelSerializer):
    sender = serializers.ReadOnlyField(source='sender.username')
    
    class Meta:
        model = Message
        fields = ['id', 'sender', 'receiver', 'encrypted_text', 'timestamp']

    def create(self, validated_data):
        sender = self.context['request'].user
        receiver = validated_data['receiver']
        message_text = self.context['request'].data['plain_text']

        # Load receiver's public key
        public_key = serialization.load_pem_public_key(receiver.public_key.encode())

        # Encrypt the message
        encrypted = public_key.encrypt(
            message_text.encode(),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        validated_data['sender'] = sender
        validated_data['encrypted_text'] = encrypted.hex()  # Store as hex string
        return super().create(validated_data)
