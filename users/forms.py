from django.contrib.auth.forms import UserCreationForm
from django import forms

from users.models import User


class Register(UserCreationForm):
    email = forms.EmailField()
    username = forms.CharField()
    password1 = forms.CharField()
    password2 = forms.CharField()


class Meta:
    Model = User
    fields = ('username', 'email', 'password1', 'password2')


class Forgot(forms.Form):
    email = forms.EmailField()

