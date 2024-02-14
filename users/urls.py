
from django.urls import path,include
from . import views
from django.contrib.auth.views import (
    PasswordResetView,
    PasswordResetDoneView,
    PasswordResetConfirmView,
    PasswordResetCompleteView
)
urlpatterns = [
    path('', views.status),
    path('api/', include([
        path('login/', views.login_user),
        path('register/', views.register),
        path('reset/', views.change_password),
        path('forgot/', views.forgotPassword),
        path('logout/', views.logout_user),
        path('confirmEmail/', views.confirm_mail),
        path('changecredentials/', views.changecredentials),

    ])),
    ]
