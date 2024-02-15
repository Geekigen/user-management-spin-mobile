import uuid
from django.contrib.auth.models import User, AbstractUser
from django.db import models

from base.models import GenericBaseModel, State

class Role(GenericBaseModel):
    uuid = models.UUIDField(max_length=100, default=uuid.uuid4, unique=True, primary_key=True, editable=False)
    state = models.ForeignKey(State, related_name="role_states", on_delete=models.CASCADE)

    def __str__(self):
        return self.name


class CustomUser(AbstractUser):
    uuid = models.UUIDField(max_length=100, default=uuid.uuid4, unique=True, primary_key=True, editable=False)
    role = models.ForeignKey(Role, on_delete=models.CASCADE, null=True)
    state = models.ForeignKey(State, on_delete=models.CASCADE, null=True)
    emailverified = models.BooleanField(default=False)

    def __str__(self):
        return self.username

    class Meta:
        verbose_name = "User Identities"


class Otp(models.Model):
    code = models.CharField(max_length=6, unique=True)
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.code


class LogType(GenericBaseModel):
    code = models.CharField(max_length=6, unique=True)

    def __str__(self):
        return self.code


class Log(GenericBaseModel):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    log_activity = models.ForeignKey(LogType, on_delete=models.CASCADE)

    def __str__(self):
        return '%s' % self.date_created


class MailOtp(models.Model):
    code = models.CharField(max_length=6, unique=True)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now=True)
