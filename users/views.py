import json

import jwt
from django.core.mail import EmailMessage
from django.forms import model_to_dict
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import logout

from base.models import State
from usermanagement import settings
from .backend.RequestEngines import check_requests
from .backend.verificationCode import generateCode
from .models import CustomUser, Otp
from datetime import datetime, timedelta
from django.contrib.auth import authenticate, login
from rest_framework.authtoken.models import Token
from django.http import JsonResponse, HttpResponseForbidden

user_service = CustomUser.objects


@csrf_exempt
def register(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            username = data.get('username')
            email = data.get('email')
            password1 = data.get('password1')
            password2 = data.get('password2')
            state_active = State.objects.get(name="Active")
            if not username or not email or not password1 or not password2:
                return JsonResponse({'message': 'Check the credentials and try again'}, status=401)

            if password1 != password2:
                return JsonResponse({'message': 'Passwords do not match'}, status=401)

            if user_service.filter(username=username).exists():
                return JsonResponse({"message": "Username already exists try another one "}, status=401)

            if user_service.filter(email=email).exists():
                return JsonResponse({"message": "email already exists try another one "}, status=401)

            user = user_service.create_user(username=username, email=email, password=password1, state=state_active)
            user.save()
            return JsonResponse({"message": "Register successful"}, status=201)
        except Exception as e:
            return JsonResponse({'message': str(e)})
    else:
        return JsonResponse({'message': 'Invalid request method'})


@csrf_exempt
def login_user(request):
    data = check_requests(request)
    username = data.get('username')
    if not username:
        return JsonResponse({"code": "404.000.000", "message": "Username not found"})
    password = data.get('password')
    if not password:
        return JsonResponse({"code": "404.000.000", "message": "Password not found"})
    user = authenticate(request, username=username, password=password)
    if not user:
        return JsonResponse({"code": "401.000.000", "message": "User not found"})
    elif user is not None:
        payload = {
            'id': user.id,
            'exp': datetime.now() + timedelta(minutes=60),
            'iat': datetime.now()
        }
        SECRET = settings.JWT_SECRET
        token = jwt.encode(payload, SECRET, algorithm='HS256')
        login(request, user)
        data = model_to_dict(user)
        json_response = JsonResponse({"code": "200.000.000", "data": data, "message": "Logged in successfully"},
                            status=200)
        json_response.set_cookie('token', token, httponly=True)
        return json_response
    else:
        return JsonResponse({"message": "Invalid request"}, status=450)
@csrf_exempt
def change_password(request):
    if request.method == "POST":
        data = json.loads(request.body)
        username = data.get('username')
        newpassword = data.get('newpassword')
        clientcode = data.get('code')
        validcode = Otp.objects.filter(code=clientcode).get()
        u = user_service.get(username=username)
        if u and validcode:
            validcodetime = validcode.date_created
            validcodetime = validcodetime.replace(tzinfo=None)
            current_time = datetime.now()
            time_diff = current_time - validcodetime
            if timedelta(minutes=10) > time_diff > timedelta(minutes=9):
                u.set_password(newpassword)
                u.save()
            else:
                return JsonResponse({"message": "otp expired generate another"}, status=450)
        else:
            return JsonResponse({"message": "Invalid code "}, status=450)
    else:
        return JsonResponse({"message": "Invalid request"}, status=450)


@csrf_exempt
def forgotPassword(request):
    if request.method == "POST":
        data = json.loads(request.body)
        email = data.get('email')
        print(email)
        if user_service.filter(email=email).exists():
            user = user_service.filter(email=email).first()
            if user:
                token = generateCode()
                otp = Otp.objects.create(code=token)
                otp.save()
                mail_subject = 'Password reset request'
                message = f'your reset code is :{token}'
                email = EmailMessage(
                    mail_subject,
                    message,
                    to=[email]
                )
                email.send()
                return JsonResponse({"message": "password sent to your mail"}, status=200)
        else:
            return JsonResponse({"message": "Invalid email"}, status=450)
    else:
        return JsonResponse({"message": "Invalid request"}, status=450)


@csrf_exempt
def logout_user(request):
    #
    from django.contrib.auth import logout

    def logout_user(request):
        logout(request)
        response = JsonResponse({"message": "Logged out successfully"})
        response.delete_cookie('token')  # Clear token from the client-side
        return response

    #
    data = json.loads(request.body)
    id = data.get('user_id')
    user = user_service.get(id=id)
    print(user.is_authenticated)
    print(request.user)
    if user.is_authenticated:
        print(request.user)
        logout(request)
        print(request.user)
        print(user.is_authenticated)
    return JsonResponse({'message': 'Someone is out '})


@csrf_exempt
def status(request):
    # valid = validapi(request)
    return ('hi')
