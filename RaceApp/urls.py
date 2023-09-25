from django.contrib import admin
from django.urls import path
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('',views.index,name='index'),
 
    path('login/', views.login, name='login'),
    
    path('signup/', views.signup, name='signup'),
    
]