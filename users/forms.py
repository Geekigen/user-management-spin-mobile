from django.contrib.auth.forms import UserCreationForm
from django import forms

from usermanagement.users.models import user


class Register(UserCreationForm):
    email = forms.EmailField()
    username = forms.CharField()
    password1 = forms.CharField()
    password2 = forms.CharField()

class Meta:
    Model = user
    fields = ('username', 'email', 'password1', 'password2')



