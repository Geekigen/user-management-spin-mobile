from django.contrib.auth.models import User
from django.core.validators import validate_email
from django.db import models

from base.models import GenericBaseModel, State


# Create your models here.
class CustomUser(User):
    state = models.ForeignKey(State, related_name="user_states", on_delete=models.CASCADE)

    def __str__(self):
        return self.username

    class Meta:
        verbose_name = "User Identities"


class Role(GenericBaseModel):
    state = models.ForeignKey(State, related_name="role_states", on_delete=models.CASCADE)

    def __str__(self):
        return self.name


class Otp(models.Model):
    code = models.CharField(max_length=6, unique=True)
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.code
