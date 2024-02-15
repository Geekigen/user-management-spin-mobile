from users.models import CustomUser

user_service = CustomUser.objects
def is_user_logged_in(user_id):
    try:
        user = user_service.get(id=user_id)
        return user.is_authenticated
    except user_service.DoesNotExist:
        return False