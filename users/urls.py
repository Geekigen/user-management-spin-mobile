
from django.urls import path,include
from . import views
urlpatterns = [
    path('', views.status),
    path('api/', include([
        path('login/', views.login_user),
        path('register/', views.register),
        path('logout/', views.logout_user),
    ])),
    ]
