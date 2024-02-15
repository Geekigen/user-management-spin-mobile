from functools import wraps
import jwt
from django.conf import settings
from django.contrib.auth.models import User
from django.http import JsonResponse

from users.models import CustomUser


def authenticate_token(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        token = request.COOKIES.get('token')
        if not token:
            return JsonResponse({"message": "Token not found. Kindly login."}, status=401)
        try:
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=['HS256'])
            user_id = payload['id']
            user = CustomUser.objects.get(id=user_id)
            request.user = user
            return view_func(request, *args, **kwargs)
        except jwt.ExpiredSignatureError:
            return JsonResponse({"message": "Token expired. Kindly login."}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({"message": "Invalid token. Try logging in."}, status=401)
        except user.DoesNotExist:
            return JsonResponse({"message": "User not found. Try logging in."}, status=401)

    return wrapper
