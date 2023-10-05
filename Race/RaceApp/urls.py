from django.urls import path
from . import views
from django.contrib.auth import views as auth_views
from django.contrib.auth.views import PasswordResetView,PasswordResetDoneView,PasswordResetConfirmView,PasswordResetCompleteView

from .views import CustomPasswordResetView,CustomPasswordResetDoneView,CustomPasswordResetConfirmView,CustomPasswordResetCompleteView

urlpatterns = [
    path('',views.index,name='index'),
    path('login/',views.login,name='login'),
    path('index/',views.index,name='index'),
    path('logout/',views.logout,name='logout'),
    path('about/',views.about,name='about'),
    path('signup/',views.signup,name='signup'),
    path('forgot', auth_views.PasswordResetView.as_view(), name='password_reset'),

    path('rider/',views.rider,name='rider'),
    
    path('password_reset/', CustomPasswordResetView.as_view(), name='password_reset'),
    path('password_reset/done/',CustomPasswordResetDoneView.as_view(),name='password_reset_done'),
    path('reset/<uidb64>/<token>/',CustomPasswordResetConfirmView.as_view(),name='password_reset_confirm'),
    path('reset/done/',CustomPasswordResetCompleteView.as_view(),name='password_reset_complete'),
    
     path('admin1/',views.admin1,name='admin1'),
      path('adminreg/',views.adminreg,name='adminreg'),
]
    
