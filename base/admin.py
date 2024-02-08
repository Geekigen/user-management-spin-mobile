from django.contrib import admin
from django.contrib.auth.models import User, Group

from .models import State

# Register your models here.
admin.site.register(State)
admin.site.unregister(User)
admin.site.unregister(Group)
