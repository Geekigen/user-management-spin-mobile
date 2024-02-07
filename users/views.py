import json

from django.forms import model_to_dict
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required

from .backend.RequestEngines import check_requests


@csrf_exempt
def register(request):
    if request.method == "POST":
        try:
            # print(request.body)
            data = json.loads(request.body)
            print(data)
            username = data.get('username')
            email = data.get('email')
            password1 = data.get('password1')
            password2 = data.get('password2')

            if not username or not email or not password1 or not password2:
                return JsonResponse({'message': 'Check the credentials and try again'})

            if password1 != password2:
                return JsonResponse({'message': 'Passwords do not match'})

            if User.objects.filter(username=username).exists():
                return JsonResponse({"message": "Username already exists try another one "})

            if User.objects.filter(email=email).exists():
                return JsonResponse({"message": "email already exists try another one "})
            # form = EmailForm(request.POST)
            # if form.is_valid():

            user = User.objects.create_user(username=username, email=email, password=password1)
            user.save()
            return JsonResponse({"message": "Register successful"}, status=201)
        except Exception as e:
            return JsonResponse({'message': str(e)})
    else:
        return JsonResponse({'message': 'Invalid request method'})

@csrf_exempt
def login_user(request):
    # if request.method == "POST":
    print(request.user)
    data = check_requests(request)
    print(request.user.is_authenticated)
    print(data)
    username = data.get('username')
    if not username:
        return JsonResponse({"code": "404.000.000", "message": "Username not found"})
    password = data.get('password')
    if not password:
        return JsonResponse({"code": "404.000.000", "message": "Password not found"})
    user = authenticate(request, username=username, password=password)
    if not user:
        return JsonResponse({"code": "404.000.000", "message": "User not found"})
    if user is not None:
        login(request, user)
        print(request.user)
        print(user.is_authenticated)
        data = model_to_dict(user)
        return JsonResponse({"code": "200.000.000", "data": data, "message": "Logged in successfully"}, status=200)
    if not user:
        return JsonResponse({"message": "user not found "}, status=404)
    else:
        return JsonResponse({"message": "Invalid request"}, status=450)

    # try:
    #     from usermanagement.users.backend.auth import Authenticate
    #     data = Authenticate().register()
    #     return JsonResponse({"data": data})
    # except Exception as ex:
    #     print(ex)
    #     return {"code": "301", "message": "An error occured while trying to register"}
    # # return JsonResponse({'message': 'Someone is logged in'})

@csrf_exempt
def change_password(request):
    if request.method == "POST":
        data = json.loads(request.body)
        username = data.get('username')
        newpassword = data.get('newpassword')
        u = User.objects.get(username=username)
        u.set_password(newpassword)
        u.save()
    else:
        return JsonResponse({"message":"Invalid request"}, status = 450)


@login_required
def logout_user(request):
    id
    logout(request)
    return JsonResponse({'message': 'Someone is out '})


def status(request):
    print(request.user)
    if not request.user.is_authenticated:
        return JsonResponse({"message": "Not logged in"})
    else:
        return JsonResponse({"message": "logged in"})
        # back to login page
