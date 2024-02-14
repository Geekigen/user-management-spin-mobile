from django.contrib.auth.models import User

from users.models import Log, LogType, CustomUser


def logit(user_name, status):
    user = CustomUser.objects.get(username=user_name)
    activity = LogType.objects.get(name=status)
    new_log = Log.objects.create(
        user=user,
        log_activity=activity,
    )
    new_log.save()

