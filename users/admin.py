from django.contrib import admin

from .models import CustomUser, Role, Otp, Log, LogType, MailOtp, CustomPermissions

admin.site.register(CustomUser)
admin.site.register(Role)
admin.site.register(Otp)
admin.site.register(LogType)
admin.site.register(Log)
admin.site.register(MailOtp)
admin.site.register(CustomPermissions)
