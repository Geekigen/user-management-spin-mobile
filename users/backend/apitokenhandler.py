import jwt
from datetime import datetime, timedelta

from django.http import JsonResponse

from usermanagement import settings


def handleToken(token):
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=['HS256'])
        user_id = payload['id']
        payload = {
            'id': user_id,
            'exp': datetime.now() + timedelta(minutes=10),
            'iat': datetime.now()
        }
        SECRET = settings.JWT_SECRET
        token = jwt.encode(payload, SECRET, algorithm='HS256')
        newToken = token
        json_response = JsonResponse({"code": "200.000.000", "message": "success"},
                                     status=200)
        json_response.set_cookie('token', newToken, httponly=True)
        return JsonResponse({"token": newToken}, status=200)
    except jwt.ExpiredSignatureError:
        return JsonResponse({"message": "Token expired. Kindly login."}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({"message": "invalid token."}, status=401)
    except:
        return JsonResponse({"message": "An error occured"}, status=401)




