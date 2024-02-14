from django.contrib import admin

from .models import CustomUser, Role, Otp, Log, LogType, MailOtp

admin.site.register(CustomUser)
admin.site.register(Role)
admin.site.register(Otp)
admin.site.register(Log)
admin.site.register(MailOtp)
