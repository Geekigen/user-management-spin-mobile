from django.contrib.auth.models import User
from django.core.validators import validate_email
from django.db import models

from base.models import State, GenericBaseModel


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
