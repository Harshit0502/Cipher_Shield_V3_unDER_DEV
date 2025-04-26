from django.db import models
from auth_system.models import KeyPair

class Message(models.Model):
    sender = models.ForeignKey(KeyPair, related_name='sent_messages', on_delete=models.CASCADE)
    receiver = models.ForeignKey(KeyPair, related_name='received_messages', on_delete=models.CASCADE)
    encrypted_text = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"From {self.sender.username} to {self.receiver.username}"
