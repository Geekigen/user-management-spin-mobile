import jwt
from django.conf import settings
from django.http import JsonResponse
from django.contrib.auth import login

def authenticate_token(view_func):
    def wrapper(request, *args, **kwargs):
        token = request.COOKIES.get('token')
        if not token:
            return JsonResponse({"message": "Token not found"}, status=401)

        try:
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=['HS256'])
            user_id = payload['id']
            user = User.objects.get(id=user_id)
            request.user = user  # Set authenticated user to request object
            return view_func(request, *args, **kwargs)
        except jwt.ExpiredSignatureError:
            return JsonResponse({"message": "Token expired"}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({"message": "Invalid token"}, status=401)
        except User.DoesNotExist:
            return JsonResponse({"message": "User not found"}, status=401)

    return wrapper

@authenticate_token
def protected_view(request):
    # Your protected view logic here
