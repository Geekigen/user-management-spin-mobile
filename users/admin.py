from django.contrib import admin

# Register your models here.
from .models import CustomUser
from .models import Role
from .models import Otp

admin.site.register(CustomUser)
admin.site.register(Role)
admin.site.register(Otp)
