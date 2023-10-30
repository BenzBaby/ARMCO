from django.urls import path,include
from . import views
from django.contrib.auth import views as auth_views
from django.contrib.auth.views import PasswordResetView,PasswordResetDoneView,PasswordResetConfirmView,PasswordResetCompleteView

from .views import CustomPasswordResetView,CustomPasswordResetDoneView,CustomPasswordResetConfirmView,CustomPasswordResetCompleteView

from django.conf import settings

from django.conf.urls.static import static

urlpatterns = [
    path('',views.index,name='index'),
    path('login/',views.login,name='login'),
    path('index/',views.index,name='index'),
    path('logout/',views.logout,name='logout'),
    path('about/',views.about,name='about'),
    path('signup/',views.signup,name='signup'),
    path('forgot', auth_views.PasswordResetView.as_view(), name='password_reset'),
    
    
    path('deactivation_email/',views.deactivation_email,name='deactivation_email'),
    path('activation_email/',views.activation_email,name='activation_email'),

    path('rider/',views.rider,name='rider'),
    path('company/',views.company,name='company'),
    path('staff/',views.staff,name='staff'),  
    
    
    path('password_reset/', CustomPasswordResetView.as_view(), name='password_reset'),
    path('password_reset/done/',CustomPasswordResetDoneView.as_view(),name='password_reset_done'),
    path('reset/<uidb64>/<token>/',CustomPasswordResetConfirmView.as_view(),name='password_reset_confirm'),
    path('reset/done/',CustomPasswordResetCompleteView.as_view(),name='password_reset_complete'),
    
    path('admin1/',views.admin1,name='admin1'),
    path('adminreg/',views.adminreg,name='adminreg'),
    path('staffview/',views.staffview,name='staffview'),  
    
    path('deactivate_user/<int:user_id>/', views.deactivate_user, name='deactivate_user'),
    path('activate_user/<int:user_id>/', views.activate_user, name='activate_user'),  
    
    path('activate/<uidb64>/<token>',views.ActivateAccountView.as_view(),name='activate'),
    
    path('social-auth/', include('social_django.urls', namespace='social')),
    
    path('all-riders/', views.all_riders, name='all_riders'),
    
    path('company/details/', views.company_details, name='company_details'),
    
    path('rider/details/', views.rider_details, name='rider_details'),
    
    path('bike_rental/', views.bike_rental, name='bike_rental'),
    
    path('edit_rider_profile/', views.edit_rider_profile, name='edit_rider_profile'),
    
    path('edit_company/', views.edit_company, name='edit_company'),
    
    path('company_payment/', views.company_payment, name='company_payment'),
    
    path('change_password/', views.change_password, name='change_password'),
    path('password_change_success/', views.password_change_success, name='password_change_success'),
    
    path('add_trackday/', views.add_trackday, name='add_trackday'),
]
    
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
