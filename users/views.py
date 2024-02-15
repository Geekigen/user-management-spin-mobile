import json

import jwt
from django.core.mail import EmailMessage
from django.forms import model_to_dict
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import logout

from base.models import State
from usermanagement import settings
from .backend.RequestEngines import check_requests
from .backend.apitokenhandler import handleToken
from .backend.logs import logit
from .backend.sendotpmail import send_Otp
from .backend.validatejwt import authenticate_token
from .backend.verificationCode import generateCode
from .models import CustomUser, Otp, Role, MailOtp
from datetime import datetime, timedelta
from django.contrib.auth import authenticate, login
from django.http import JsonResponse

user_service = CustomUser.objects


@csrf_exempt
def register(request):
    data = check_requests(request)
    username = data.get('username')
    email = data.get('email')
    user_role = data.get('user_role')
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
    role = Role.objects.get(name=user_role)
    token = generateCode()
    user = user_service.create_user(username=username, email=email, role=role,
                                    password=password1, state=state_active)
    send_Otp(email, token)
    user.save()
    logit(username, "registered")
    return JsonResponse({"message": "Register successful.Check your email for confirmation code"}, status=201)


@csrf_exempt
def confirm_mail(request):
    data = check_requests(request)
    mail = data.get('email')
    confirmationcode = data.get('code')
    registered = user_service.filter(email=mail).get()
    validcode = MailOtp.objects.filter(code=confirmationcode, user=registered).exists()
    if validcode:
        if registered.emailverified:
            return JsonResponse({"message": "Email already confirmed."}, status=200)
        else:
            registered.emailverified = True
            registered.save()
            return JsonResponse({"message": "Email confirmation successful."}, status=200)
    else:
        return JsonResponse({"message": "Invalid email or Verification code try again."}, status=401)


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
        custom = user_service.filter(username=user).get()
        if not custom.emailverified:
            return JsonResponse({"message": "Email not verified.Verify your email"}, status=401)

        logit(username, "loggedin")
        payload = {
            'id': str(user.uuid),
            'exp': datetime.now() + timedelta(minutes=1),
            'iat': datetime.now()
        }
        SECRET = settings.JWT_SECRET
        token = jwt.encode(payload, SECRET, algorithm='HS256')
        login(request, user)
        data = model_to_dict(custom)
        data['uuid'] = user.uuid
        data['token'] = token
        json_response = JsonResponse({"code": "200.000.000", "data": data, "message": "Logged in successfully"},
                                     status=200)
        json_response.set_cookie('token', token, httponly=True)
        return json_response
    else:
        return JsonResponse({"message": "Invalid request"}, status=450)


@csrf_exempt
@authenticate_token
def change_password(request):
    data = check_requests(request)
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
            logit(username, "changedpassword")
        else:
            return JsonResponse({"message": "otp expired generate another"}, status=450)
    else:
        return JsonResponse({"message": "Invalid code "}, status=450)


@csrf_exempt
def verfyTokens(request):
    data = check_requests(request)
    token = data.get('token')
    handleToken(token)


@csrf_exempt
@authenticate_token
def changecredentials(request):
    data = check_requests(request)
    token = request.COOKIES.get('token')
    if not token:
        return JsonResponse({"message": "Token not found kindly login"}, status=401)
    payload = jwt.decode(token, settings.JWT_SECRET, algorithms=['HS256'])
    user_id = payload['id']
    user = user_service.get(id=user_id)
    username = user.username
    newusername = data.get('newusername')
    email = data.get('email')
    user_role = data.get('user_role')
    password1 = data.get('password1')
    password2 = data.get('password2')
    state_active = State.objects.get(name="Active")
    if not newusername or not email or not password1 or not password2:
        return JsonResponse({'message': 'Check the credentials and try again'}, status=401)

    if password1 != password2:
        return JsonResponse({'message': 'Passwords do not match'}, status=401)

    if user_service.filter(username=newusername).exists():
        return JsonResponse({"message": "Username already exists try another one "}, status=401)

    if user_service.filter(email=email).exists():
        return JsonResponse({"message": "email already exists try another one "}, status=401)
    token = generateCode()
    user = CustomUser.objects.get(pk=user_id)
    user.username = newusername
    user.email = email
    user.role = user_role
    user.set_password(password2)
    send_Otp(email, token)
    user.save()
    logit(username, "changedcredials")
    return JsonResponse({"message": "Reset successful.Check your New Email for confirmation code"}, status=201)


@csrf_exempt
def forgotPassword(request):
    if request.method == "POST":
        data = json.loads(request.body)
        email = data.get('email')
        user = user_service.filter(email=email).first()
        if user:
            username = user.username
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
            logit(username, "forgotpassword")
            return JsonResponse({"message": "password sent to your mail"}, status=200)
        else:
            return JsonResponse({"message": "Invalid email"}, status=450)
    else:
        return JsonResponse({"message": "Invalid request"}, status=450)


@csrf_exempt
def logout_user(request):
    logout(request)
    response = JsonResponse({"message": "Logged out successfully"})
    token = request.COOKIES.get('token')
    if not token:
        return JsonResponse({"message": "Token not found kindly login"}, status=401)
    payload = jwt.decode(token, settings.JWT_SECRET, algorithms=['HS256'])
    user_id = payload['id']
    user = user_service.get(id=user_id)
    username = user.username
    logit(username, "loggedout")
    response.delete_cookie('token')
    return response


@csrf_exempt
@authenticate_token
def status(request):
    return JsonResponse({"message": "hi"})
