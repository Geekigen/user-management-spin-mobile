from functools import wraps

import jwt
from django.conf import settings
from django.contrib.auth.models import User
from django.http import JsonResponse


def authenticate_token(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        token = request.COOKIES.get('token')
        if not token:
            return JsonResponse({"message": "Token not found kindly login"}, status=401)
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=['HS256'])

        try:
            user_id = payload['id']
            user = User.objects.get(id=user_id)
            request.user = user
            return view_func(request, *args, **kwargs)
        except jwt.ExpiredSignatureError:
            return JsonResponse({"message": "Token expired kindly login"}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({"message": "Invalid token try logging in"}, status=401)
        except User.objects.filter(id=payload['id']).exists():
            return JsonResponse({"message": "User not found try loging in "}, status=401)

    return wrapper
