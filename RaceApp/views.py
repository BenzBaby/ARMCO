from django.shortcuts import render
from django.db import IntegrityError
from django.urls import reverse
from .models import CustomUser
from django.contrib import messages
from django.shortcuts import render,redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate ,login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.views import PasswordResetView,PasswordResetConfirmView,PasswordResetDoneView,PasswordResetCompleteView
from django.urls import reverse_lazy
from django.db.models import Q  # Import Q for complex queries
from django.shortcuts import render, redirect,get_object_or_404
from .utils import *
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.utils.encoding import force_bytes,force_str
from django.template.loader import render_to_string
from django.views.generic import View
from django.contrib.auth.models import User

# Create your views here.

from social_django.models import UserSocialAuth

from django.views import View
from django.contrib.auth.backends import ModelBackend
# #email
from django.conf import settings
from django.core.mail import EmailMessage
#threading
import threading


from .utils import TokenGenerator,generate_token


class EmailThread(threading.Thread):
    def __init__(self, email_message):
        self.email_message = email_message
        super().__init__()  #Call the parent class's __init_ method

    def run(self):
        self.email_message.send()


class CustomPasswordResetView(PasswordResetView):
    template_name = 'password_reset_form.html'  # Your template for the password reset form
    email_template_name = 'password_reset_email.html'  # Your email template for the password reset email
    success_url = reverse_lazy('password_reset_done')  # URL to redirect after successful form submission
class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'password_reset_confirm.html'  # Your template for password reset confirmation form
    success_url = reverse_lazy('password_reset_complete')  # URL to redirect after successful password reset
class CustomPasswordResetDoneView(PasswordResetDoneView):
    template_name = 'password_reset_done.html'  # Your template for password reset done page
class CustomPasswordResetCompleteView(PasswordResetCompleteView):
    template_name = 'password_reset_complete.html'  # Your template for password reset complete page
from django.shortcuts import render
from .models import Trackday
from django.utils import timezone

def index(request):
    # Get today's date
    current_date = timezone.now().date()

    # Retrieve upcoming trackdays, ordered by date
    upcoming_trackdays = Trackday.objects.filter(date__gte=current_date).order_by('date')

    # Calculate the time remaining for the next upcoming trackday
    next_trackday = None
    remaining_days = None

    if upcoming_trackdays:
        next_trackday = upcoming_trackdays[0]
        remaining_days = (next_trackday.date - current_date).days

    return render(request, 'index.html', {
        'next_trackday': next_trackday,
        'remaining_days': remaining_days,
    })


def staff(request):
    return render(request, 'staff.html')
def signup(request):
    if request.method == "POST":
        username=request.POST.get('username')
        #fullname = request.POST.get('firstname')
       
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirmPassword = request.POST.get('confirm-password')
        role = request.POST.get('role')  # Add role selection in your signup form
       # phone_number = request.POST.get('phoneNumber')
        #address = request.POST.get('address')
      
        

        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, "Email already exists")
        elif CustomUser.objects.filter(username=username).exists():
            messages.error(request, "Username already exists")
        elif password != confirmPassword:
            messages.error(request, "Passwords do not match")
        else:
            user = CustomUser(username=username,email=email,role=role)  # Change role as needed
            user.set_password(password)
            user.is_active=False  #make the user inactive
            user.save()
            current_site=get_current_site(request)  
            email_subject="Activate your account"
            message=render_to_string('activate.html',{
                   'user':user,
                   'domain':current_site.domain,
                   'uid':urlsafe_base64_encode(force_bytes(user.pk)),
                   'token':generate_token.make_token(user)
            })


            email_message=EmailMessage(email_subject,message,settings.EMAIL_HOST_USER,[email],)
            EmailThread(email_message).start()
            messages.info(request,"Active your account by clicking the link send to your email")

           
            return redirect("login")
    return render(request,'signup.html')

class ActivateAccountView(View):
    def get(self,request,uidb64,token):
        try:
            uid=force_str(urlsafe_base64_decode(uidb64))
            user=CustomUser.objects.get(pk=uid)
        except Exception as identifier:
            user=None
        if user is not None and generate_token.check_token(user,token):
            user.is_active=True
            user.save()
            messages.info(request,"Account activated sucessfully")
            return redirect('login')
        return render(request,"activatefail.html")    

# def login(request):
#     if request.method == "POST":
#         username = request.POST.get('username')
#         password = request.POST.get('password')

#         user = authenticate(request, username=username, password=password)

#         if user is not None:
#             auth_login(request, user)
#             request.session['username'] = username
#             if user.role == 'rider':
            
#                 return redirect("rider")  # Replace 'rider' with the name of your home page URL
#             elif user.role == 'company':
#                 return redirect("company") 
#         else:
#             messages.error(request, "Invalid login credentials")

#     response = render(request, 'login.html')
#     response['Cache-Control'] = 'no-store, must-revalidate'
#     return response

            
# def rider(request):
    
#     if 'username' in request.session:
#        response = render(request, 'rider.html')
#        response['Cache-Control'] = 'no-store, must-revalidate'
#        return response
#     else:
#        return redirect('index') 


from django.shortcuts import render, redirect
from django.http import HttpResponse
from .models import TrackdayRegistration
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from .models import Trackday
@login_required


def rider(request):
    if 'username' in request.session:
        User = get_user_model()
        user = User.objects.get(username=request.session['username'])

        existing_registration = TrackdayRegistration.objects.filter(rider=user).first()

        # Query available trackday dates from the database
        trackday_dates = Trackday.objects.all()

        if request.method == 'POST':
            rider_name = request.POST['ridername']
            trackday_date = request.POST['trackdate']
            number_of_trackdays = request.POST['numberoftrackdays']
            vehiclerental = request.POST.get('vehiclerental') == 'yes'
            gearrental = request.POST.get('gearrental') == 'yes'
            licensepdf = request.FILES.get('licensepdf')
            profilepicture = request.FILES.get('profilepicture')

            if existing_registration:
                if vehiclerental:
                    return redirect('bike_list')
                else:
                    return redirect('payment_norent')
            else:
                registration = TrackdayRegistration(
                    rider=user,
                    rider_name=rider_name,
                    trackday_date=trackday_date,
                    number_of_trackdays=number_of_trackdays,
                    vehiclerental=vehiclerental,
                    gearrental=gearrental,
                    licensepdf=licensepdf,
                    profilepicture=profilepicture
                )
                registration.save()
                if vehiclerental:
                    return redirect('bike_list')
                else:
                    return redirect('payment_norent')

        return render(request, 'rider.html', {'existing_registration': existing_registration, 'trackday_dates': trackday_dates})
    else:
        return redirect('index')


from django.shortcuts import render
from .models import TrackdayRegistration

def all_riders(request):
    # Retrieve all rider details from the database
    rider_details = TrackdayRegistration.objects.all()

    # Pass the rider details to the template for rendering
    context = {'rider_details': rider_details}
    return render(request, 'all_riders.html', context)



from datetime import datetime

from datetime import datetime
from django.shortcuts import render, redirect
from django.http import HttpResponse
from .models import TrackdayRegistration, Trackday # Import necessary models
from django.contrib.auth import get_user_model

def edit_rider_profile(request):
    if 'username' in request.session:
        User = get_user_model()
        user = User.objects.get(username=request.session['username'])

        existing_registration = TrackdayRegistration.objects.filter(rider=user).first()

        if request.method == 'POST':
            # Retrieve updated details from the POST data
            trackdate = request.POST.get('trackdate', '') # Change to 'trackday_date'
            number_of_trackdays = request.POST.get('numberoftrackdays', '')
            vehiclerental = request.POST.get('vehiclerental', '') == 'yes'
            gearrental = request.POST.get('gearrental', '') == 'yes'
            licensepdf = request.FILES.get('licensepdf')
            profilepicture = request.FILES.get('profilepicture')

            # Convert the trackdate to the correct format (YYYY-MM-DD)
            try:
                trackdate = datetime.strptime(trackdate, '%Y-%m-%d').strftime('%Y-%m-%d')
            except ValueError:
                return HttpResponse("Invalid date format. It must be in the format 'YYYY-MM-DD'.")

            if existing_registration:
                # Update the existing registration with the new details
                existing_registration.trackday_date = trackdate
                existing_registration.number_of_trackdays = number_of_trackdays
                existing_registration.vehiclerental = vehiclerental
                existing_registration.gearrental = gearrental

                if licensepdf:
                    existing_registration.licensepdf = licensepdf
                if profilepicture:
                    existing_registration.profilepicture = profilepicture

                existing_registration.save()
                return redirect('bike_list')  # Redirect to the rider's profile page

        # Retrieve the available trackday dates
        trackday_dates = Trackday.objects.all()

        return render(request, 'edit_rider_profile.html', {
            'existing_registration': existing_registration,
            'trackday_dates': trackday_dates,  # Pass trackday dates to the template
        })

    else:
        return redirect('index')

   

from django.shortcuts import render, redirect
from django.http import HttpResponse
from .models import CompanyTrackdayRegistration  # Import the CompanyTrackdayRegistration model
from django.contrib.auth.decorators import login_required  # Import the login_required decorator


 # Import your form if you have one

def company(request):
    if 'username' in request.session:
        User = get_user_model()
        user = User.objects.get(username=request.session['username'])

        # Check if the user already has a registration
        existing_registration = CompanyTrackdayRegistration.objects.filter(user=user).first()

        if existing_registration:
            # Redirect to the index page or display a message as needed
            return redirect('company_payment')
        if request.method == 'POST':
        # Get form data from POST request
            company_name = request.POST.get('companyname')
            trackday_date = request.POST.get('trackdate')
            rider_details_pdf = request.FILES.get('riderdetailspdf')

        # Create a new CompanyTrackdayRegistration object
            registration = CompanyTrackdayRegistration(
                user=user,
                company_name=company_name,
                trackday_date=trackday_date,
                rider_details_pdf=rider_details_pdf
            )
            registration.save()

            # Redirect or provide a success message
            return redirect('company_payment')

        return render(request, 'company.html')
    else:
        return redirect('about')
    
    
from django.shortcuts import render, redirect
from .models import CompanyTrackdayRegistration

def edit_company(request):
    if 'username' in request.session:
        User = get_user_model()
        user = User.objects.get(username=request.session['username'])

        # Check if the user already has a registration
        existing_registration = CompanyTrackdayRegistration.objects.filter(user=user).first()

        if existing_registration:
            if request.method == 'POST':
                # Get the updated details from the POST request
                # company_name = request.POST.get('companyname')
                trackday_date = request.POST.get('trackdate')
                rider_details_pdf = request.FILES.get('riderdetailspdf')

                # Update the existing registration with the new details
                # existing_registration.company_name = company_name
                existing_registration.trackday_date = trackday_date

                if rider_details_pdf:
                    existing_registration.rider_details_pdf = rider_details_pdf

                existing_registration.save()

                # Redirect or provide a success message
                return HttpResponse("Details updated successfully.")

            return render(request, 'edit_company.html', {'existing_registration': existing_registration})
        else:
            # Handle the case where the user does not have an existing registration
            return redirect('about')
    else:
        return redirect('about')


    
       
def logout(request):
    auth_logout(request) # Use the logout function to log the user out
    return redirect('index')  # Re   


def log(request):
    if request.user.is_authenticated:
        logout(request)
    return redirect('login')


@login_required(login_url='login')
def logview(request):
     return render(request,'index.html')
# Create your views here.
def about(request):
    return render(request, 'about.html')
def admin1(request):
    return render(request,'admin1.html')

from django.shortcuts import render
from .models import CustomUser, UserProfile
from django.db.models import Q

def adminreg(request):
    role_filter = request.GET.get('role')
    
    # Filter users based on role and exclude superusers
    if role_filter:
        if role_filter == "rider":
            profiles = CustomUser.objects.filter(Q(role=role_filter) & ~Q(is_superuser=True))
        else:
            profiles = CustomUser.objects.filter(Q(role=role_filter) & ~Q(is_superuser=True))
    else:
        profiles = CustomUser.objects.filter(~Q(is_superuser=True))  # Exclude superusers

    # Create a list of dictionaries to store lap times and categories for each user
    lap_time_and_category = []
    
    for profile in profiles:
        user_profile = UserProfile.objects.filter(user=profile).first()
        if user_profile:
            lap_time = user_profile.time
            category = user_profile.category if user_profile.category else "N/A"
        else:
            lap_time = None
            category = "N/A"

        lap_time_and_category.append({'user_id': profile.id, 'lap_time': lap_time, 'category': category})

    return render(request, 'adminreg.html', {'profiles': profiles, 'lap_time_and_category': lap_time_and_category})

# views.py
from django.shortcuts import render
from .models import Trackday  # Import your Trackday model or adjust the import
from django.shortcuts import render, get_object_or_404
from .models import Trackday  # Update this to match your model's import path

def add_trackday(request):
    date_added_successfully = False  # Initialize the success flag

    if request.method == 'POST':
        # Process the form data and add/remove the trackday from the database
        action = request.POST.get('action', None)

        if action == 'add':
            # Add a new trackday
            date = request.POST['date']
            if Trackday.objects.filter(date=date).exists():
                # Date already exists, handle the error or display a message
                date_added_successfully = False
            else:
                # Date is unique, create a new trackday and save it
                trackday = Trackday(date=date)
                trackday.save()
                date_added_successfully = True
        elif action == 'remove':
            # Remove an existing trackday
            trackday_id = request.POST.get('trackday_id', None)
            if trackday_id:
                trackday = get_object_or_404(Trackday, pk=trackday_id)
                trackday.delete()
                date_added_successfully = True

    # Retrieve all added trackdays
    trackdays = Trackday.objects.all()  # Modify this to match your model's name

    return render(request, 'add_trackday.html', {
        'date_added_successfully': date_added_successfully,
        'trackdays': trackdays,
    })

# def deactivate_user(request, user_id):
#     user = get_object_or_404(CustomUser, id=user_id)
#     if user.is_active:
#         user.is_active = False
#         user.save()
#         messages.success(request, f"User '{user.username}' has been deactivated.")
#     else:
#         messages.warning(request, f"User '{user.username}' is already deactivated.")
#     return redirect('adminreg')

from django.core.mail import send_mail
from django.contrib import messages
from django.shortcuts import render, redirect
from django.shortcuts import get_object_or_404
from .models import CustomUser  # Import your User model

def deactivate_user(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)
    if user.is_active:
        user.is_active = False
        user.save()

        # Send deactivation email
        subject = 'Account Deactivation'
        message = 'Your account has been deactivated by the admin.'
        from_email = 'benzbaby10@gmail.com'  # Replace with your email
        recipient_list = [user.email]
        html_message = render_to_string('deactivation_email.html', {'user': user})

        send_mail(subject, message, from_email, recipient_list, html_message=html_message)

        messages.success(request, f"User '{user.username}' has been deactivated, and an email has been sent.")
    else:
        messages.warning(request, f"User '{user.username}' is already deactivated.")
    return redirect('adminreg')

def deactivation_email(request):
    return render(request, 'deactivation_email.html')


from django.core.mail import send_mail
from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
from django.template.loader import render_to_string
from django.utils.html import strip_tags

def activate_user(request, user_id):
    user = get_object_or_404(CustomUser, id=user_id)

    if not user.is_active:
        user.is_active = True
        user.save()
        messages.success(request, f"User '{user.username}' has been activated by the admin, and an email has been sent.")
        
        # Send activation email to the user
        subject = "Account Activation"
        html_message = render_to_string('activation_email.html', {'user': user})
        plain_message = strip_tags(html_message)
        from_email = "benzbaby10@gmail.com"  # Update with your email
        recipient_list = [user.email]
        send_mail(subject, plain_message, from_email, recipient_list, html_message=html_message)

    else:
        messages.warning(request, f"User '{user.username}' is already active.")

    return redirect('adminreg')


def activation_email(request):
    return render(request, 'activation_email.html')

# def activate_user(request, user_id):
#     user = get_object_or_404(CustomUser, id=user_id)
#     if not user.is_active:
#         user.is_active = True
#         user.save()
#         messages.success(request, f"User '{user.username}' has been activated.")
#     else:
#         messages.warning(request, f"User '{user.username}' is already active.")
#     return redirect('adminreg')

def google_authenticate(request):
    # Handle the Google OAuth2 authentication process
    # ...

    # After successful authentication, create or get the user
    try:
        user_social = UserSocialAuth.objects.get(provider='google-oauth2', user=request.user)
        user = user_social.user
    except UserSocialAuth.DoesNotExist:
        user = request.user

    # Set a default role for users signing in with Google (e.g., "Patient")
    user.role = 'rider'
    user.save()
    print(f"User role set to: {user.role}")

    # Redirect to the desired page (phome.html for Patient role)
    if user.role == 'rider':
        return redirect('rider')  # Make sure you have a URL named 'phome'
    
from django.contrib import messages
from django.contrib.auth import authenticate, login as auth_login
from django.shortcuts import render, redirect

from RaceApp.models import TrackdayRegistration

def is_registered_rider(username):
    try:
        rider = TrackdayRegistration.objects.get(rider__username=username)
        return True  # User is a registered rider
    except TrackdayRegistration.DoesNotExist:
        return False 
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate
from django.contrib.auth import login as auth_login
 
from django.contrib.auth import authenticate, login as auth_login
from django.contrib import messages
from .models import StaffProfile
from django.shortcuts import redirect
from django.shortcuts import redirect
from django.contrib.auth import authenticate, login as auth_login
from django.contrib import messages
from django.shortcuts import render
def custom_login(request):
    username = ''  # Initialize username variable

    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')

        # Check if the user is an admin
        if username == "admin" and password == "admin":
            request.session['username'] = username
            return redirect("adminreg")  # Redirect to the admin dashboard

        user = authenticate(request, username=username, password=password)
        if user is not None:
            auth_login(request, user)
            request.session['username'] = username
            if user.role == 'rider':
                # Check if the user is a registered rider
                is_registered = is_registered_rider(username)  # Replace with your logic
                if is_registered:
                    # Check if the user has rented a vehicle
                    vehiclerental = request.POST.get('vehiclerental')
                    if vehiclerental == "no":
                        return redirect("payment_norent")  # Redirect to the payment_norent page
                    else:
                        # Check if the user has a previous registration with 'vehiclerental' as 'yes'
                        has_previous_rental = TrackdayRegistration.objects.filter(rider=user, vehiclerental=True).exists()
                        has_previous_non_rental = TrackdayRegistration.objects.filter(rider=user, vehiclerental=False).exists()
                        if has_previous_rental:
                            return redirect("bike_list")  # Redirect to the bike_list page
                        elif has_previous_non_rental:
                            return redirect("payment_norent")  # Redirect to the payment_norent page
                        else:
                            return redirect("rider")  # Redirect to the rider dashboard
                else:
                    return redirect("rider")  # Redirect to the rider dashboard
            elif user.role == 'company':
                return redirect("company")  # Redirect to the company dashboard

        messages.error(request, "Invalid login credentials")

    context = {'login_name': username}
    response = render(request, 'login.html', context)
    response['Cache-Control'] = 'no-store, must-revalidate'
    return response


# Import necessary models or make sure they are imported in your actual code
from RaceApp.models import Booking

def has_booked_vehicle(username):
    try:
        user = User.objects.get(username=username)
        # Check if there is a booking for the user
        booking = Booking.objects.filter(user=user).first()
        return booking is not None
    except User.DoesNotExist:
        return False


# from .models import BikeRental  # Import your BikeRental model

# def has_rented_bike(username):
#     # Check if there is a bike rental record for the user
#     return BikeRental.objects.filter(rider__username=username).exists()


  
  

from django.shortcuts import render
from django.contrib import messages
from .models import CustomUser, UserProfile
from datetime import timedelta

def format_timedelta(td):
    if td is not None:
        minutes, seconds = divmod(td.seconds, 60)
        return f"{minutes:02}:{seconds:02}"
    return "N/A"

from datetime import timedelta
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import CustomUser, UserProfile

from datetime import timedelta
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import CustomUser, UserProfile

def staffview(request):
    # Handle filtering based on the 'role' parameter in the GET request
    role = request.GET.get('role', '')  # Get the role value from the request

    # Query the database to get user profiles based on the role filter
    if role:
        profiles = CustomUser.objects.filter(role=role)
    else:
        profiles = CustomUser.objects.all()

    # Create a list to store formatted lap times for each user
    formatted_lap_times = []

    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        lap_time_str = request.POST.get('lap_time')

        if user_id and lap_time_str:
            user = CustomUser.objects.get(id=user_id)

            # Parse the lap time string into a time duration
            try:
                minutes, seconds = map(int, lap_time_str.split(':'))
                lap_time = timedelta(minutes=minutes, seconds=seconds)
            except ValueError:
                lap_time = None

            if lap_time is not None:
                # Save the lap time for the user
                user_profile, created = UserProfile.objects.get_or_create(user=user)
                user_profile.time = lap_time

                # Automatically determine the category based on lap time
                if lap_time < timedelta(minutes=2):
                    user_profile.category = 'Pro Level'
                elif lap_time < timedelta(minutes=3):
                    user_profile.category = 'Intermediate Level'
                elif lap_time < timedelta(minutes=4):
                    user_profile.category = 'Beginner Level'
                else:
                    user_profile.category = 'Unknown'

                user_profile.save()

                # Optionally, add a success message
                messages.success(request, f"Lap time added for {user.username}")
            else:
                # Handle form validation errors
                messages.error(request, "Invalid lap time format. Please use MM:SS.")

    # Iterate through profiles to get formatted lap times
    for profile in profiles:
        user_profile = UserProfile.objects.filter(user=profile).first()

        # Check if user_profile is not None
        if user_profile:
            lap_time = user_profile.time

            # Format the lap time as "MM:SS" using the custom function
            formatted_time = format_timedelta(lap_time) if lap_time else "N/A"
            formatted_lap_times.append(formatted_time)
        else:
            formatted_lap_times.append("N/A")

    context = {
        'profiles': profiles,
        'formatted_lap_times': formatted_lap_times,
    }

    return render(request, 'staffview.html', context)


from django.shortcuts import render
from .models import CompanyTrackdayRegistration

def company_details(request):
    company_details = CompanyTrackdayRegistration.objects.all()
    return render(request, 'company_details.html', {'company_details': company_details})


from django.shortcuts import render
from .models import TrackdayRegistration

def rider_details(request):
    riders = TrackdayRegistration.objects.all()
    return render(request, 'rider_details.html', {'riders': riders})




# from django.shortcuts import render

# def bike_rental(request):
#     if 'username' in request.session:
#         User = get_user_model()
#         user = User.objects.get(username=request.session['username'])

#         existing_registration = TrackdayRegistration.objects.filter(rider=user).first()

#         if existing_registration:
#             profile_picture_url = existing_registration.profilepicture.url
#             rider_username = user.username
#         else:
#             profile_picture_url = None
#             rider_username = ""
#         return render(request, 'bike_list.html', {'profile_picture_url': profile_picture_url,'rider_username': rider_username})
#     else:
#         return redirect('index')


def company_payment(request):
    return render(request, 'company_payment.html')


from django.contrib.auth import update_session_auth_hash
from django.http import HttpResponse
from django.contrib import messages



def change_password(request):
    if request.method == "POST":
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if request.user.check_password(current_password):
            if new_password == confirm_password:
                request.user.set_password(new_password)
                request.user.save()
                update_session_auth_hash(request, request.user)
                messages.success(request, "Password changed successfully.")
                return redirect("password_change_success")
            else:
                messages.error(request, "New password and confirmation password do not match.")
                return HttpResponse("New password and confirmation password do not match.", status=400)
        else:
            messages.error(request, "Current password is incorrect.")
            return HttpResponse("Current password is incorrect.", status=400)

    return render(request, "change_password.html")



from django.shortcuts import render


def password_change_success(request):
    return render(request, 'password_change_success.html')


# bikes/views.py

from django.shortcuts import render, redirect
from .models import Bike
from .forms import BikeForm
from django.contrib import messages

def add_or_edit_bike(request, bike_id=None):
    if bike_id:
        bike = Bike.objects.get(pk=bike_id)
    else:
        bike = None

    if request.method == 'POST':
        form = BikeForm(request.POST, request.FILES, instance=bike)
        if form.is_valid():
            form.save()
            messages.success(request, 'Vehicle added successfully!')
        
           
    else:
        form = BikeForm(instance=bike)

    return render(request, 'add_or_edit_bike.html', {'form': form, 'bike': bike})

from django.shortcuts import render
from .models import Bike
from django.contrib.auth import get_user_model
from .models import TrackdayRegistration  # Import your TrackdayRegistration model

from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model
from .models import TrackdayRegistration, Bike

def bike_list(request):
    if 'username' in request.session:
        User = get_user_model()
        user = User.objects.get(username=request.session['username'])

        existing_registration = TrackdayRegistration.objects.filter(rider=user).first()

        if existing_registration:
            profile_picture_url = existing_registration.profilepicture.url
            rider_username = user.username
        else:
            profile_picture_url = None
            rider_username = ""

        # Retrieve the list of bikes
        bikes = Bike.objects.all()

        for bike in bikes:
            if bike.available_count <= 0:
                bike.can_book = False
            else:
                bike.can_book = True
                

        return render(request, 'bike_list.html', {
            'profile_picture_url': profile_picture_url,
            'rider_username': rider_username,
            'bikes': bikes,
        })
    else:
        return redirect('index')



from django.shortcuts import render
from .models import Bike  # Import your Bike model

def admin_bike_view(request):
    # Fetch all bikes from the database
    bikes = Bike.objects.all()

    return render(request, 'admin_bike_view.html', {'bikes': bikes})


from django.shortcuts import render, redirect
from django.contrib import messages
from .models import StaffProfile

from django.contrib.auth import login

from django.core.mail import send_mail
from django.shortcuts import render, redirect

from django.contrib.auth import login, authenticate
from django.contrib.auth.models import User

from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from RaceApp.models import CustomUser, StaffProfile
from django.core.mail import send_mail

from django.contrib.auth import authenticate, login
from django.core.mail import send_mail
from django.shortcuts import render, redirect
from .models import StaffProfile

def staff_signup(request):
    error_message = ''  # Initialize error_message here

    if request.method == 'POST':
        username = request.POST.get('username', '')
        email = request.POST.get('email', '')
        password = request.POST.get('password', '')
        phone_number = request.POST.get('phone_number', '')
        address = request.POST.get('address', '')
        date_of_birth = request.POST.get('date_of_birth', '')
        profile_picture = request.FILES.get('profile_picture')
        # Process the Aadhaar card image upload
        aadhaar_card = request.FILES.get('aadhaar_card')

        if not username or not email or not password:
            error_message = "All fields are required."
        else:
            # Create a CustomUser object and set the username, email, and password
            user = CustomUser.objects.create_user(username=username, email=email)
            user.set_password(password)
            user.save()

            # Create a StaffProfile instance and set it to pending
            staff = StaffProfile(username=username, email=email, status='pending')
            staff.phone_number = phone_number
            staff.address = address
            staff.date_of_birth = date_of_birth
            staff.aadhaar_card = aadhaar_card  # Save the Aadhaar card image
            staff.profile_picture = profile_picture
            staff.save()

            # Send an email to the admin for approval or rejection
            approval_link = f'http://{request.get_host()}/approve_staff/{staff.id}/'
            rejection_link = f'http://{request.get_host()}/reject_staff/{staff.id}/'
            send_mail(
                'Staff Approval Request',
                f'Please approve or reject the staff member {username} with email {email}.\n'
                f'Approval Link: {approval_link}\n'
                f'Rejection Link: {rejection_link}',
                email,  # Use staff's provided email as the sender
                ['armcotracks@gmail.com'],  # Admin's email
                fail_silently=False,
            )

            # Authenticate the staff member and log them in
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)

            return render(request, 'staff_login.html')  # Redirect to a success page

    return render(request, 'staff_signup.html', {'error_message': error_message})

from django.shortcuts import render, redirect
from .models import StaffProfile  # Adjust this import to match your model
from django.contrib import messages

def approve_staff(request, staff_id):
    try:
        staff = StaffProfile.objects.get(pk=staff_id)
        staff.status = 'Approved'
        staff.save()
        messages.success(request, f'Staff member {staff.username} has been approved.')
    except StaffProfile.DoesNotExist:
        messages.error(request, 'Staff member not found.')
    
    return redirect('approve_staff_list')
from django.contrib import messages

def reject_staff(request, staff_id):
    try:
        staff = StaffProfile.objects.get(pk=staff_id)
        staff.status = 'Rejected'
        staff.save()
        messages.success(request, f'Staff member {staff.username} has been rejected.')
    except StaffProfile.DoesNotExist:
        messages.error(request, 'Staff member not found.')

    return redirect('approve_staff_list')


from django.shortcuts import render


from .models import StaffProfile

def approve_staff_list(request):
    approved_staff = StaffProfile.objects.filter(status='Approved')
    rejected_staff = StaffProfile.objects.filter(status='Rejected')
    
    return render(request, 'approve_staff_list.html', {
        'approved_staff': approved_staff,
        'rejected_staff': rejected_staff,
    })


from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect

from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from RaceApp.models import CustomUser, StaffProfile
from django.core.mail import send_mail

from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from RaceApp.models import CustomUser, StaffProfile
from django.core.mail import send_mail
from django.contrib import messages
def staff_login(request):
    error_message = ''  # Initialize error_message here

    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = authenticate(request, username=username, password=password)
        if user is not None:
            # Check if the staff member is approved
            staff = StaffProfile.objects.get(username=username)
            if staff.status == 'Approved':
                login(request, user)
                # Redirect to a success page or the desired destination
                return redirect('staffview')
            else:
                error_message = "Your account has not been approved yet. Please wait for approval."
        else:
            # Handle login failure, e.g., show an error message
            error_message = "Invalid username or password"

    return render(request, 'staff_login.html', {'error_message': error_message})


from django.shortcuts import render
from .models import StaffProfile

def staff_list(request):
    staff_members = StaffProfile.objects.all()  # Query all staff members
    context = {'staff_members': staff_members}
    return render(request, 'staff_list.html', context)
from django.shortcuts import render, redirect
from .models import TrackdayRegistration, PaymentRecord
from django.contrib.auth import get_user_model
from django.utils import timezone  # Import timezone

def payment_norent(request):
    if 'username' in request.session:
        User = get_user_model()
        user = User.objects.get(username=request.session['username'])
        
        if PaymentRecord.objects.filter(user=user).exists():
            # User has already booked, redirect to the 'already_booked' page
            return HttpResponse("You've already booked a track day. If you believe this is a mistake, please contact customer support.")


        registration = TrackdayRegistration.objects.filter(rider=user).first()

        if registration:
            rental_amount = registration.number_of_trackdays * 1000

            # Retrieve registration details
            rider_name = registration.rider_name
            trackday_date = registration.trackday_date
            number_of_trackdays = registration.number_of_trackdays
            vehiclerental = registration.vehiclerental

            # Calculate the total amount (if additional calculations are needed)
            total_amount = rental_amount  # You can modify this calculation as necessary
            confirmed_date = None  # Initialize confirmed_date

            if request.method == 'POST':
                # Payment is confirmed, set the confirmed_date
                confirmed_date = timezone.now()

                # Create a PaymentRecord instance and save it with the confirmed date
                payment_record = PaymentRecord(
                    rider_name=rider_name,
                    trackday_date=trackday_date,
                    number_of_trackdays=number_of_trackdays,
                    rental_amount=rental_amount,
                    amount=total_amount,
                    confirmed_date=confirmed_date,  # Set the confirmed date
                )
                payment_record.save()

            return render(request, 'payment_norent.html', {
                'registration': registration,
                'rental_amount': rental_amount,
                'total_amount': total_amount,
                'confirmed_date': confirmed_date,  # Include confirmed date in the context
            })

    return redirect('index')


def edit_rider_norental(request):
    if 'username' in request.session:
        User = get_user_model()
        user = User.objects.get(username=request.session['username'])

        existing_registration = TrackdayRegistration.objects.filter(rider=user).first()

        if request.method == 'POST':
            # Retrieve updated details from the POST data
            trackdate = request.POST.get('trackdate', '') # Change to 'trackday_date'
            number_of_trackdays = request.POST.get('numberoftrackdays', '')
           
           
            licensepdf = request.FILES.get('licensepdf')
            profilepicture = request.FILES.get('profilepicture')

            # Convert the trackdate to the correct format (YYYY-MM-DD)
            try:
                trackdate = datetime.strptime(trackdate, '%Y-%m-%d').strftime('%Y-%m-%d')
            except ValueError:
                return HttpResponse("Invalid date format. It must be in the format 'YYYY-MM-DD'.")

            if existing_registration:
                # Update the existing registration with the new details
                existing_registration.trackday_date = trackdate
                existing_registration.number_of_trackdays = number_of_trackdays
               

                if licensepdf:
                    existing_registration.licensepdf = licensepdf
                if profilepicture:
                    existing_registration.profilepicture = profilepicture

                existing_registration.save()
                return redirect('payment_norent')  # Redirect to the rider's profile page

        # Retrieve the available trackday dates
        trackday_dates = Trackday.objects.all()

        return render(request, 'edit_rider_norental.html', {
            'existing_registration': existing_registration,
            'trackday_dates': trackday_dates,  # Pass trackday dates to the template
        })

    else:
        return redirect('index')
    
# from django.shortcuts import render, redirect
# from .models import Booking

# from .models import Bike, Booking  # Import your Bike and Booking models
# from django.contrib import messages
# from django.shortcuts import redirect, render

# from .models import Bike, Booking, TrackdayRegistration
# from django.contrib import messages
# from django.shortcuts import render, redirect
# # @login_required
# def book_bike(request, bike_id):
#     try:
#         bike = Bike.objects.get(id=bike_id)
#     except Bike.DoesNotExist:
#         messages.error(request, 'Bike not found.')
#         return redirect('bike_list')

#     if request.method == 'POST':
#        if request.user.is_authenticated:
#         rider = request.user

#         # Replace this with the logic to get the selected TrackdayRegistration instance
#         # For example, you can retrieve it based on the user and the trackday date.
#         selected_date = request.POST.get('trackday_date')  # Replace this line
#         try:
#             trackday_registration = TrackdayRegistration.objects.get(
#                 rider=rider, trackday_date=selected_date
#             )

#             if trackday_registration:
#                 booking = Booking(bike=bike, rider=rider, trackdayregistration=trackday_registration)
#                 booking.save()
#                 messages.success(request, 'Booking successful!')
#                 return redirect('booking_confirmation')
#             else:
#                 messages.error(request, 'Trackday registration not found.')
#                 return redirect('trackday_registration')  # Redirect to the trackday registration page
#         except TrackdayRegistration.DoesNotExist:
#             messages.error(request, 'Trackday registration not found.')
#             return redirect('trackday_registration')  # Redirect to the trackday registration page
#     else:
#         messages.error(request, 'Please log in to book a bike.')
#         return redirect('login')


#     return render(request, 'bookbike.html', {'bike': bike})



# from django.shortcuts import render, get_object_or_404
# from .models import BookingConfirmation

# from django.shortcuts import render, get_object_or_404
# from .models import BookingConfirmation

# def all_booking_confirmation(request, confirmation_id):
#     # Retrieve the booking confirmation using the provided confirmation_id
#     confirmation = get_object_or_404(BookingConfirmation, pk=confirmation_id)

#     # Now you can use the 'confirmation' object to display its details in the template

#     return render(request, 'all_booking_confirmation.html', {'confirmation': confirmation})


# from django.shortcuts import render, redirect
# from .models import Bike, Booking
# from django.contrib import messages

# from django.shortcuts import render, redirect
# from .models import Bike, Booking, BookingConfirmation
# from django.contrib import messages

# from django.core.mail import send_mail
# from django.http import HttpResponse
# from django.shortcuts import render, redirect
# from django.contrib import messages
# from datetime import datetime
# from .models import Bike, Booking, BookingConfirmation
# @login_required
# def book_bike(request, bike_id):
#     try:
#         bike = Bike.objects.get(id=bike_id)
#     except Bike.DoesNotExist:
#         messages.error(request, 'Bike not found.')
#         return redirect('bike_list')

#     if request.method == 'POST':
#         if bike.available_count > 0:
#             if request.user.is_authenticated:
#                 rider = request.user
#                 rider_name = rider.username  # Get the rider's name

#                 # Check if the rider has already made a booking for this bike
#                 if Booking.objects.filter(bike=bike, rider=rider).exists():
#                     message = 'You have already made a booking for this bike.'
#                     return HttpResponse(message, status=409)  # Return a 409 Conflict HTTP response

#                 # Create a booking instance
#                 booking = Booking(bike=bike, rider=rider)
#                 booking.save()

#                 # Decrease the available count
#                 bike.available_count -= 1
#                 bike.save()

#                 # Capture form data
#                 booking_date = request.POST['booking_date']
#                 additional_details = request.POST.get('additional_details', '')  # Get additional details (optional)

#                 # Create a booking confirmation instance
#                 confirmation = BookingConfirmation(booking=booking, confirmation_date=datetime.now(), additional_details=additional_details)
#                 confirmation.save()

#                 # Send an email notification to the rider
#                 subject = 'Booking Confirmation'
#                 message = f'Your booking for the bike "{bike.name}" has been confirmed.'
#                 from_email = 'benzbaby10@gmail.com'  # Replace with your email
#                 recipient_list = [rider.email]  # Use the rider's email address

#                 send_mail(subject, message, from_email, recipient_list, fail_silently=False)

#                 messages.success(request, 'Booking and confirmation successful!')
#                 return redirect('login')
#             else:
#                 messages.error(request, 'Please log in to book a bike.')
#                 return redirect('login')  # Redirect to the login page
#         else:
#             messages.error(request, 'This bike is already booked.')

#     return render(request, 'bookbike.html', {'bike': bike})


# from django.shortcuts import render
# from .models import Booking, TrackdayRegistration

# from django.shortcuts import render
# from .models import TrackdayRegistration, Booking, CustomUser
# @login_required
# def rider_finaldetails(request):
#     # Retrieve all riders who have made bookings
#     riders = CustomUser.objects.filter(booking__isnull=False).distinct()
    
#     # Create a list to store details for all riders
#     riders_details = []
    
#     for rider in riders:
#         trackday_registration = TrackdayRegistration.objects.filter(rider=rider).first()
#         bookings = Booking.objects.filter(rider=rider)
        
#         # Add rider details to the list
#         rider_details = {
#             'rider': rider,
#             'trackday_registration': trackday_registration,
#             'bookings': bookings,
#         }
#         riders_details.append(rider_details)
    
#     return render(request, 'rider_finaldetails.html', {'riders_details': riders_details})

from django.shortcuts import render
from .models import Booking

def booking_details(request):
    # Fetch all booking objects
    bookings = Booking.objects.all()

    return render(request, 'booking_details.html', {'bookings': bookings})

from .models import BikeRental  # Import your BikeRental model
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import redirect


def rent_bike(request):
    # Check if the user is a rider and has not rented a bike
    username = request.user.username
    has_rented = BikeRental.objects.filter(rider=request.user).exists()

    if request.user.role == 'rider' and not has_rented:
        # Create a new BikeRental instance and save it to the database
        bike_rental = BikeRental(rider=request.user)
        bike_rental.save()
        return redirect("bike_list")  # Redirect to the bike rental page after renting

    return HttpResponse("You are not eligible to rent a bike or you have already rented one.")


from django.shortcuts import render, redirect
from .models import Bike, Booking, BookingConfirmation
from django.contrib import messages

# def book_bike(request, bike_id):
#     try:
#         bike = Bike.objects.get(id=bike_id)
#     except Bike.DoesNotExist:
#         messages.error(request, 'Bike not found.')
#         return redirect('bike_list')

#     if request.method == 'POST':
#         if request.user.is_authenticated:
#             rider = request.user
#             booking = Booking(bike=bike, rider=rider)
#             booking.save()

#             # Create a BookingConfirmation instance and associate it with the booking
#             confirmation = BookingConfirmation(booking=booking)
#             confirmation.save()

#             messages.success(request, 'Booking successful!')
#             return redirect('all_booking_confirmations')
#         else:
#             messages.error(request, 'Please log in to book a bike.')
#             return redirect('login')  # Redirect to the login page

#     return render(request, 'bookbike.html', {'bike': bike})
# # views.py
# views.py
# views.py

from django.db.models import F, ExpressionWrapper, FloatField
from django.shortcuts import render
from .models import BookingConfirmation, TrackdayRegistration
from django.shortcuts import render
from .models import BookingConfirmation, TrackdayRegistration

from django.shortcuts import render
from .models import BookingConfirmation, TrackdayRegistration
from datetime import date

from .models import RiderDetails  # Import the RiderDetails model


# def all_booking_confirmations(request):
#     booking_confirmations = BookingConfirmation.objects.all()

#     for confirmation in booking_confirmations:
#         try:
#             trackday_registration = TrackdayRegistration.objects.get(rider=confirmation.booking.rider)
#             confirmation.trackday_registration = trackday_registration

#             current_date = date.today()
#             trackday_date = trackday_registration.trackday_date

#             if current_date < trackday_date:
#                 confirmation.status = "Upcoming"
#             elif current_date > trackday_date:
#                 confirmation.status = "Over"
#             else:
#                 confirmation.status = "Active"

#             if confirmation.booking.bike and trackday_registration:
#                 confirmation.total_rent = confirmation.booking.bike.rent_per_day * trackday_registration.number_of_trackdays
#             else:
#                 confirmation.total_rent = 0

#             if confirmation.trackday_registration:
#                 confirmation.total_trackday_amount = 1000 if trackday_registration.number_of_trackdays == 1 else 2000
#             else:
#                 confirmation.total_trackday_amount = 0

#         except TrackdayRegistration.DoesNotExist:
#             # Handle the case where there is no related TrackdayRegistration
#             confirmation.status = "N/A"

#             # Set total amounts to 0 when there's no trackday registration
#             confirmation.total_rent = 0
#             confirmation.total_trackday_amount = 0

#         # Calculate the total amount
#         confirmation.total_amount = confirmation.total_rent + confirmation.total_trackday_amount

#         # Create and save a RiderDetails object for this confirmation
#         rider_details = RiderDetails(
#             rider=confirmation.booking.rider,
#             confirmation_date=confirmation.confirmation_date,
#             trackdays=confirmation.trackday_registration.number_of_trackdays if confirmation.trackday_registration else 0,
#             trackday_date=trackday_date if confirmation.trackday_registration else None,
#             current_status=confirmation.status,
#             vehicle_name=confirmation.booking.bike.name if confirmation.booking.bike else "N/A",
#             rental_amount_per_day=confirmation.booking.bike.rent_per_day if confirmation.booking.bike else 0,
#             number_of_trackdays=confirmation.trackday_registration.number_of_trackdays if confirmation.trackday_registration else 0,
#             total_rental_amount=confirmation.total_rent,
#             total_trackday_amount=confirmation.total_trackday_amount,
#             total_amount=confirmation.total_amount,
#         )
#         rider_details.save()

#     return render(request, 'all_booking_confirmations.html', {'booking_confirmations': booking_confirmations})



# views.py
from django.shortcuts import render
from .models import Bike


def update_bike_availability(request):
    bikes = Bike.objects.all()
    if request.method == 'POST':
        # Update the available counts based on staff input
        for bike in bikes:
            new_count = request.POST.get(f'available_count_{bike.id}')
            if new_count is not None:
                bike.available_count = new_count
                bike.save()

    context = {'bikes': bikes}
    return render(request, 'update_bike_availability.html', context)
# from django.shortcuts import render, get_object_or_404
# from .models import BookingConfirmation
# from django.contrib.auth.models import User  # Assuming you're using the built-in User model

# def rider_booking_confirmations(request, rider_id):
#     rider = get_object_or_404(CustomUser, id=rider_id)  # Replace User with your User model
#     booking_confirmations = BookingConfirmation.objects.filter(booking__rider=rider)

#     context = {
#         'rider': rider,
#         'booking_confirmations': booking_confirmations,
#     }

#     return render(request, 'rider_booking_confirmations.html', context)


# views.py
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import Bike, TrackdayRegistration

# views.py

from django.http import HttpResponse
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from .models import TrackdayRegistration, Bike, Bookingconfirmed
from django.core.mail import send_mail
from django.conf import settings
# views.py

@login_required
def book(request, bike_id):
    # Check if the user has an existing booking with cancellation status 'pending'
    existing_pending_booking = Bookingconfirmed.objects.filter(
        rider=request.user,
        cancellation_status='pending'
    )

    if existing_pending_booking.exists():
        return HttpResponse('You have a pending booking. You cannot make a new booking at this time.')

    try:
        trackday_registration = TrackdayRegistration.objects.get(rider=request.user)
    except TrackdayRegistration.DoesNotExist:
        trackday_registration = None

    selected_bike = get_object_or_404(Bike, pk=bike_id, available_count__gt=0)
    booking = TrackdayRegistration.objects.get(rider=request.user)
    total_rent = selected_bike.rent_per_day * trackday_registration.number_of_trackdays

    total_trackday_fee = 0
    if trackday_registration.number_of_trackdays == 1:
        total_trackday_fee = 1000
    elif trackday_registration.number_of_trackdays == 2:
        total_trackday_fee = 2000

    overall_amount = total_rent + total_trackday_fee

    if request.method == 'POST':
        # Handle the booking confirmation

        # Confirm the booking and update bike availability
        booking = Bookingconfirmed(
            rider=request.user,
            bike=selected_bike,
            total_rental_amount=total_rent,
            total_trackday_fee=total_trackday_fee,
            total_amount=overall_amount,
            trackday_date=trackday_registration.trackday_date,
            number_of_trackdays=trackday_registration.number_of_trackdays,
        )
        booking.save()

        selected_bike.available_count -= 1
        selected_bike.save()

        # Send confirmation email
        subject = 'Booking Confirmation'
        message = f'Thank you for booking your track day. Your total amount is: ${overall_amount}'
        from_email = settings.DEFAULT_FROM_EMAIL  # Use your email settings
        recipient_list = [request.user.email]

        send_mail(subject, message, from_email, recipient_list)

        # Redirect to a confirmation page or show a success message
        return HttpResponse('Booking successful. Thank you!')

    return render(request, 'book.html', {
        'trackday_registration': trackday_registration,
        'selected_bike': selected_bike,
        'total_trackday_fee': total_trackday_fee,
        'total_rent': total_rent,
        'overall_amount': overall_amount,
        'booking': booking,
    })




from django.shortcuts import render, redirect
from .models import TrackdayRegistration, Bike,Bookingconfirmed
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags


@login_required
def confirm_booking(request, bike_id):
    try:
        trackday_registration = TrackdayRegistration.objects.get(rider=request.user)
    except TrackdayRegistration.DoesNotExist:
        trackday_registration = None

    bike = Bike.objects.get(pk=bike_id)

    if not bike.is_available:
        return redirect('book')  #
    
    if Bookingconfirmed.objects.filter(rider=request.user, bike=bike).exists():
        return HttpResponse('You have already booked this bike. You cannot book the same bike again.')


    # Calculate the total rent amount for the selected bike
    total_rent = bike.rent_per_day * trackday_registration.number_of_trackdays

    # Calculate the total trackday fee
    total_trackday_fee = 0
    if trackday_registration.number_of_trackdays == 1:
        total_trackday_fee = 1000
    elif trackday_registration.number_of_trackdays == 2:
        total_trackday_fee = 2000

    # Calculate the overall amount
    overall_amount = total_rent + total_trackday_fee

    if request.method == 'POST':
        booking = Bookingconfirmed(
            rider=request.user,
            bike=bike,
            total_rental_amount=total_rent,
            total_trackday_fee=total_trackday_fee,
            total_amount=overall_amount,
            trackday_date=trackday_registration.trackday_date, 
            number_of_trackdays=trackday_registration.number_of_trackdays, 
            
        )
        booking.save()
        bike.available_count -= 1
        bike.save()

        subject = 'Booking Confirmation'
        message = 'Thank you for booking your track day. Your total amount is: $' + str(overall_amount)
        from_email = 'benzbaby10@gmail.com'  # Replace with your email address
        recipient_list = [request.user.email]  # Get the rider's email from the user model

        send_mail(subject, message, from_email, recipient_list)
        return HttpResponse('Booking successful. Thank you!')

    return render(request, 'confirm_booking.html', {
        'trackday_registration': trackday_registration,
        'bike': bike,
        'total_trackday_fee': total_trackday_fee,
        'total_rent': total_rent,
        'overall_amount': overall_amount,
        'number_of_trackdays': trackday_registration.number_of_trackdays,  # Pass the number_of_trackdays to the template

    })



# views.py
from django.shortcuts import render
from .models import Bookingconfirmed
from django.db.models import Q
from django.db.models import Q

def confirmed_bookings(request):
    # Retrieve search parameters from the request
    rider_name = request.GET.get('rider_name')
    trackday_date = request.GET.get('trackday_date')
    number_of_trackdays = request.GET.get('number_of_trackdays')
    vehicle_name = request.GET.get('vehicle_name')
    confirmed_date = request.GET.get('confirmed_date')
    status = request.GET.get('status')
    total_amount = request.GET.get('total_amount')
    
    # Start with all confirmed bookings
    confirmed_bookings = Bookingconfirmed.objects.filter(~Q(cancellation_status='cancelled'))

    # Apply filters based on search parameters
    if rider_name:
        confirmed_bookings = confirmed_bookings.filter(rider__username__icontains=rider_name)

    if trackday_date:
        confirmed_bookings = confirmed_bookings.filter(trackday_date=trackday_date)

    if number_of_trackdays:
        confirmed_bookings = confirmed_bookings.filter(number_of_trackdays=number_of_trackdays)

    if vehicle_name:
        confirmed_bookings = confirmed_bookings.filter(bike__name__icontains=vehicle_name)

    if confirmed_date:
        # Convert the confirmed_date string to a datetime object
        confirmed_date = datetime.strptime(confirmed_date, "%Y-%m-%d")
        
        # Filter by date range (assuming confirmed_date is a DateTimeField)
        confirmed_bookings = confirmed_bookings.filter(confirmed_date__date=confirmed_date)

    if status:
        confirmed_bookings = confirmed_bookings.filter(status__icontains=status)

    if total_amount:
        confirmed_bookings = confirmed_bookings.filter(total_amount=float(total_amount))    

    return render(request, 'confirmed_bookings.html', {'confirmed_bookings': confirmed_bookings})



# views.py

from django.shortcuts import render, get_object_or_404, redirect
from .models import Bookingconfirmed
# views.py

from django.shortcuts import render, get_object_or_404, redirect
from .models import Bookingconfirmed

from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse
from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse
from django.utils import timezone
from django.core.mail import send_mail

def cancel_booking(request, booking_id):
    booking = get_object_or_404(Bookingconfirmed, pk=booking_id)

    # Check if the booking is already canceled
    if booking.cancellation_status == 'cancelled':
        return HttpResponse("This booking has already been canceled.")

    if request.method == 'POST':
        # Update the cancellation status and cancelled_date
        booking.cancellation_status = 'cancelled'
        booking.cancelled_date = timezone.now()
        booking.save()

        # Send an email to the rider
        subject = 'Booking Cancellation Notification'
        message = f'Hello {booking.rider.username},\n\nYour booking for {booking.bike.name} has been cancelled.'
        from_email = 'benzbaby10@gmail.com.com'
        recipient_list = [booking.rider.email]

        send_mail(subject, message, from_email, recipient_list)

        return HttpResponse("Booking Canceled Successfully!")

    return render(request, 'cancel_booking.html', {'booking': booking})

# views.py
from django.shortcuts import render
from .models import Bookingconfirmed
# views.py

from django.shortcuts import render
from .models import Bookingconfirmed

def canceled_bookings(request):
    canceled_bookings = Bookingconfirmed.objects.filter(cancellation_status='cancelled')
    return render(request, 'canceled_bookings.html', {'canceled_bookings': canceled_bookings})


@login_required
def individualinfo(request):
    bookings = Bookingconfirmed.objects.filter(rider=request.user)
    return render(request, 'individualinfo.html', {'bookings': bookings})
