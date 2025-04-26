from django.contrib.auth.models import AbstractUser
from django.db import models
from django.contrib.auth.models import User

class KeyPair(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    public_key = models.TextField()
    private_key = models.TextField()  # Optional, only store if encrypted

    def __str__(self):
        return f"KeyPair for {self.user.username}"
