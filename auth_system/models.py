from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    public_key = models.TextField(blank=True, null=True)
    private_key_encrypted = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.username
