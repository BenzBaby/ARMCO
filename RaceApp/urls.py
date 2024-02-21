from django.urls import path,include
from . import views
from django.contrib.auth import views as auth_views
from django.contrib.auth.views import PasswordResetView,PasswordResetDoneView,PasswordResetConfirmView,PasswordResetCompleteView

from .views import CustomPasswordResetView,CustomPasswordResetDoneView,CustomPasswordResetConfirmView,CustomPasswordResetCompleteView

from django.conf import settings

from django.conf.urls.static import static

urlpatterns = [
    path('',views.index,name='index'),
    path('login/',views.custom_login,name='login'),
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
    
    # path('bike_rental/', views.bike_rental, name='bike_rental'),
    
    path('edit_rider_profile/', views.edit_rider_profile, name='edit_rider_profile'),
    
    path('edit_company/', views.edit_company, name='edit_company'),
    
    path('company_payment/', views.company_payment, name='company_payment'),
    
    path('change_password/', views.change_password, name='change_password'),
    path('password_change_success/', views.password_change_success, name='password_change_success'),
    
    path('add_trackday/', views.add_trackday, name='add_trackday'),
    
    path('add_or_edit_bike/', views.add_or_edit_bike, name='add_or_edit_bike'),
    
    path('bike_list/', views.bike_list, name='bike_list'),
    
    path('admin_bike_view/', views.admin_bike_view, name='admin_bike_view'),
    
    path('staff_signup/', views.staff_signup, name='staff_signup'),
    
    path('approve_staff/', views.approve_staff_list, name='approve_staff_list'),
    path('approve_staff/<int:staff_id>/', views.approve_staff, name='approve_staff'),
    path('reject_staff/<int:staff_id>/', views.reject_staff, name='reject_staff'),
    
    path('staff_login/', views.staff_login, name='staff_login'),
    
    path('staff_list/', views.staff_list, name='staff_list'),
    
    path('payment_norent/', views.payment_norent, name='payment_norent'),
    
    path('edit_rider_norental/', views.edit_rider_norental, name='edit_rider_norental'),
    
    # path('booking_confirmation/', views.booking_confirmation, name='booking_confirmation'),
    
    # path('book_bike/<int:bike_id>/', views.book_bike, name='book_bike'),
    
    # path('rider_finaldetails/', views.rider_finaldetails, name='rider_finaldetails'),
    path("booking_details/", views.booking_details, name="booking_details"),
    
    # path('all_booking_confirmations/', views.all_booking_confirmations, name='all_booking_confirmations'),
    
    path('update_bike_availability/', views.update_bike_availability, name='update_bike_availability'),
    
    # path('rider/<int:rider_id>/booking_confirmations/', views.rider_booking_confirmations, name='rider_booking_confirmations'),

     path('book/<int:bike_id>/', views.book, name='book'),
    
    path('confirm_booking/<int:bike_id>/', views.confirm_booking, name='confirm_booking'),
    
    path('confirmed_bookings/', views.confirmed_bookings, name='confirmed_bookings'),
    
    path('cancel_booking/<int:booking_id>/', views.cancel_booking, name='cancel_booking'),

    path('canceled_bookings/', views.canceled_bookings, name='canceled_bookings'),
    
    path('individualinfo/', views.individualinfo, name='individualinfo'),
    
    path('payment/<int:booking_id>/', views.payment, name='payment'),
    
    path('rules/', views.rules, name='rules'),
    
    path('generate_laptime_dataset/', views.generate_laptime_dataset, name='generate_laptime_dataset'),

    path('input_date/', views.input_date, name='input_date'),
    
    path('leaderboard/', views.leaderboard, name='leaderboard'),
    
    path('trackdaycancel/', views.trackdaycancel, name='trackdaycancel'),
    
    path('display_pdf/', views.display_pdf, name='display_pdf'),
    
    path('generate_pdf/', views.generate_pdf, name='generate_pdf'),
    
    path('trackriders/', views.trackriders, name='trackriders'),
    
    path('save_race_time/', views.save_race_time, name='save_race_time'),  
    
    path('store_lap_times/', views.store_lap_times, name='store_lap_times'),
    
    path('raceresult/', views.raceresult, name='raceresult'),
    
    path('companyinvite/', views.company_invite, name='companyinvite'),
    path('send_invite/', views.send_invite, name='send_invite'),
    
    path('companysignup/', views.companysignup, name='companysignup'),
    
    path('enter_racing_riders_list/', views.enter_racing_riders_list, name='enter_racing_riders_list'), 
    
    path('companyracetime/', views.companyracetime, name='companyracetime'),
    
    path('display_rider_times/', views.display_rider_times, name='display_rider_times'),
    
]
    
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
