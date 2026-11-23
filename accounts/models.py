from django.contrib.auth.models import User
from django.db import models


class Profile(models.Model):
    """Extra info about a user (one profile per user)."""

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    organisation = models.CharField(max_length=100, blank=True)
    bio = models.TextField(max_length=300, blank=True)

    def __str__(self):
        return f"Profile of {self.user.username}"
