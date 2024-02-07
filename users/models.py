from django.core.validators import validate_email
from django.db import models

# Create your models here.
class user(models.Model):
    username = models.CharField(max_length=200, null =False)
    password = models.CharField(max_length=200, null =False)
    email = models.EmailField(validators=[validate_email],max_length=200, null =False)
    firstname = models.CharField(max_length=200, null =False)
    lastname = models.CharField(max_length=200, null =False)
    # role = models.ForeignKey()
    date_created_at = models.DateTimeField(max_length=200, null =False)

    def __str__(self):
        return self.username

class role(models.Model):
    name = models.CharField(max_length=200, null=False)
    datecreated= models.DateTimeField(max_length=200, null=False)
    def __str__(self):
        return self.name