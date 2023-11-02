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
def index(request):
    return render(request, 'index.html')

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
               return redirect('bike_list')
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
                return redirect('bike_list')

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

@login_required
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

def add_trackday(request):
    date_added_successfully = False  # Initialize the success flag

    if request.method == 'POST':
        # Process the form data and add the trackday to the database
        date = request.POST['date']
        
        # Check if a trackday with the same date already exists
        if Trackday.objects.filter(date=date).exists():
            # Date already exists, handle the error or display a message
            date_added_successfully = False
        else:
            # Date is unique, create a new trackday and save it
            trackday = Trackday(date=date)
            trackday.save()
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
def custom_login(request):
    username = '' 
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')

        if username == "admin" and password == "admin":
            # Admin login credentials are fixed
            request.session['username'] = username
            return redirect("adminreg")  # Redirect to the admin dashboard

       

        user = authenticate(request, username=username, password=password)
        if user is not None:
            auth_login(request, user)
            request.session['username'] = username
            if user.role == 'rider':
                # Check if the user is a rider
                # You can check if they are registered as a rider here
                is_registered = is_registered_rider(username)# Replace this with code to check if the user is a registered rider
                if is_registered:
                    return redirect("bike_list")  # Redirect to the bike rental page
                else:
                    return redirect("rider")  # Redirect to the rider dashboard
            elif user.role == 'company':
                return redirect("company")  # Redirect to the company dashboard

        messages.error(request, "Invalid login credentials")
    context = {'login_name': username} 

    response = render(request, 'login.html', context)
    response['Cache-Control'] = 'no-store, must-revalidate'
    return response

    



  
  

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


@login_required
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

        # Here, you should retrieve the list of bikes or whatever context data you need
        # For example, if you have a Bike model:
        bikes = Bike.objects.all()

        return render(request, 'bike_list.html', {
            'profile_picture_url': profile_picture_url,
            'rider_username': rider_username,
            'bikes': bikes,  # Add your list of bikes here
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

def staff_signup(request):
    error_message = ''  # Initialize error_message here

    if request.method == 'POST':
        # Process the form data and perform validation
        username = request.POST['username']
        email = request.POST.get('email', '')  # Use .get method with a default value
        password = request.POST['password']

        if not username or not email or not password:
            error_message = "All fields are required."
        else:
            # Create a CustomUser object and set the username, email, and password
            user = CustomUser.objects.create_user(username=username, email=email)
            user.set_password(password)
            user.save()

            # Create a StaffProfile instance and set it to pending
            staff = StaffProfile(username=username, email=email, status='pending')
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
