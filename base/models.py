
import uuid

from django.db import models


# Create your models here.
class BaseModel(models.Model):
    uuid = models.UUIDField(max_length=100, default=uuid.uuid4, unique=True, primary_key=True,editable=False)
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.uuid

    class Meta:
        abstract = True


class GenericBaseModel(BaseModel):
    name = models.CharField(max_length=100)
    description = models.TextField(null=True, blank=True)

    class Meta:
        abstract = True


class State(GenericBaseModel):

    def __str__(self):
        return self.name