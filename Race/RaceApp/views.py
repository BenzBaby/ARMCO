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
def signup(request):
    if request.method == "POST":
        username=request.POST.get('username')
        #fullname = request.POST.get('firstname')
       
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirmPassword = request.POST.get('confirm-password')
       # phone_number = request.POST.get('phoneNumber')
        #address = request.POST.get('address')
      
        

        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, "Email already exists")
        elif CustomUser.objects.filter(username=username).exists():
            messages.error(request, "Username already exists")
        elif password != confirmPassword:
            messages.error(request, "Passwords do not match")
        else:
            user = CustomUser(username=username,email=email,role='RIDER')  # Change role as needed
            user.set_password(password)
            user.save()
            messages.success(request, "Registered successfully")
            return redirect("login")
    return render(request,'signup.html')

def login(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            auth_login(request, user)
            request.session['username'] = username
            messages.success(request, "Login successful!")
            return redirect("rider")  # Replace 'rider' with the name of your home page URL
        else:
            messages.error(request, "Invalid login credentials")

    response = render(request, 'login.html')
    response['Cache-Control'] = 'no-store, must-revalidate'
    return response
            
def rider(request):
   if 'username' in request.session:
       response = render(request, 'rider.html')
       response['Cache-Control'] = 'no-store, must-revalidate'
       return response
   else:
       return redirect('index') 
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

def adminreg(request):
    role_filter = request.GET.get('role')
    if role_filter:
        profiles = CustomUser.objects.filter(role=role_filter)
    else:
        profiles = CustomUser.objects.all()

    return render(request, 'adminreg.html', {'profiles': profiles})

