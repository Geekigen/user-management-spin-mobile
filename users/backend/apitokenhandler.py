import jwt
from datetime import datetime, timedelta

from django.http import JsonResponse

from usermanagement import settings


def handleToken(token):
    payload = jwt.decode(token, settings.JWT_SECRET, algorithms=['HS256'])
    user_id = payload['id']
    if jwt.ExpiredSignatureError == "Signature has expired":
        return JsonResponse({"message": "Token expired. Kindly login."}, status=401)
    elif jwt.InvalidTokenError:
        return JsonResponse({"message": "Invalid token. Try logging in."}, status=401)

    payload = {
        'id': user_id,
        'exp': datetime.now() + timedelta(minutes=1),
        'iat': datetime.now()
    }
    SECRET = settings.JWT_SECRET
    token = jwt.encode(payload, SECRET, algorithm='HS256')
    newToken = token
    return JsonResponse({"token": newToken}, status=200)

