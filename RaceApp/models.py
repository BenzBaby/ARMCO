from django.contrib.auth.models import AbstractUser
from django.db import models
from django.contrib.auth.models import User
from django.conf import settings

class CustomUser(AbstractUser):
    # Add custom fields here if needed
    role = models.CharField(max_length=15)  # For custom user roles, if needed

    def __str__(self):
        return self.username  # You can use any field for representation

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'


from django.db import models
from django.conf import settings

class TrackdayRegistration(models.Model):
    rider = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    rider_name = models.CharField(max_length=255)
    trackday_date = models.DateField()
    number_of_trackdays = models.PositiveIntegerField(default=1, choices=[(1, '1'), (2, '2')])
    gearrental = models.BooleanField(default=False)
    vehiclerental = models.BooleanField(default=False)
    
    licensepdf = models.FileField(upload_to='licenses/', blank=True, null=True)
    
    profilepicture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)


    def __str__(self):
        return self.rider_name


class CompanyTrackdayRegistration(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)  # Link to the user who is registering
    company_name = models.CharField(max_length=255)
    trackday_date = models.DateField()
    rider_details_pdf = models.FileField(upload_to='rider_details_pdfs/')

    def __str__(self):
        return self.company_name

from django.db import models
from django.contrib.auth.models import User
from django.conf import settings

class UserProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    time = models.DurationField(null=True, blank=True)
    category = models.CharField(max_length=20, blank=True, null=True)
    lap_time_entered_at = models.DateTimeField(auto_now_add=True)  
    
    def __str__(self):
        return f"{self.user.username}'s Lap Time: {self.time}, Category: {self.category}, Entered At: {self.lap_time_entered_at}"


# models.py
from django.db import models

class Trackday(models.Model):
    date = models.DateField()
    # Add other fields as needed

# bikes/models.py

from django.db import models

class Bike(models.Model):
    name = models.CharField(max_length=100)
    displacement = models.CharField(max_length=50)
    max_power = models.CharField(max_length=50)
    max_torque = models.CharField(max_length=50)
    additional_features = models.TextField()
    rent_per_day = models.DecimalField(max_digits=10, decimal_places=2)
    image = models.ImageField(upload_to='bike_images/')
    available_count = models.PositiveIntegerField(default=0)
    is_available = models.BooleanField(default=True)  # Add this field
from django.db import models

from django.db import models

class StaffProfile(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    )

    username = models.CharField(max_length=50)
    email = models.EmailField(unique=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')

    # Additional fields
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    date_of_birth = models.DateField(blank=True, null=True)

    # Add a field for Aadhaar card image upload
    aadhaar_card = models.ImageField(upload_to='aadhaar_cards/', blank=True, null=True)
    joining_date = models.DateField(auto_now_add=True)
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)
    def __str__(self):
        return self.username

    
from django.db import models
from django.contrib.auth.models import User
from django.conf import settings
from datetime import datetime

class Booking(models.Model):
    bike = models.ForeignKey(Bike, on_delete=models.CASCADE)
    rider = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    booked_date = models.DateField(default=datetime.now)
    trackdayregistration = models.ForeignKey(
        TrackdayRegistration, on_delete=models.SET_NULL, blank=True, null=True
    )
    is_completed = models.BooleanField(default=False)

    def __str__(self):
        return f"Booking for {self.bike.name} by {self.rider.username}"


    def get_bike_image_url(self):
        return self.bike.image.url  # Method to get the bike's image URL

    def get_bike_rent(self):
        return self.bike.rent_per_day  # Method to get the rent of the bike
from django.db import models
from django.contrib.auth.models import User  # Assuming you're using the built-in User model

class BikeRental(models.Model):
    rider = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    rented_at = models.DateTimeField(auto_now_add=True)

    # Add other fields related to the bike rental if necessary

    def __str__(self):
        return f'{self.rider.username} - {self.rented_at}'
from django.db import models
from django.db import models
from .models import Booking

class BookingConfirmation(models.Model):
    booking = models.OneToOneField(Booking, on_delete=models.CASCADE)
    confirmation_date = models.DateField(default=datetime.now)

    additional_details = models.TextField(blank=True, null=True)
    trackday_registration = models.ForeignKey(TrackdayRegistration, on_delete=models.SET_NULL, null=True, blank=True)
    total_rent = models.DecimalField(max_digits=10, decimal_places=2, default=0) 
    status = models.CharField(max_length=10, choices=[('Active', 'Active'), ('Over', 'Over')], default='Active')
    def __str__(self):
        return f"Confirmation for {self.booking.bike.name} by {self.booking.rider.username}"
from django.db import models
from django.contrib.auth.models import User

class RiderDetails(models.Model):
    rider = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    confirmation_date = models.DateField()
    trackdays = models.PositiveIntegerField()
    trackday_date = models.DateField()
    current_status = models.CharField(max_length=10)
    vehicle_name = models.CharField(max_length=100)
    rental_amount_per_day = models.DecimalField(max_digits=10, decimal_places=2)
    number_of_trackdays = models.PositiveIntegerField()
    total_rental_amount = models.DecimalField(max_digits=10, decimal_places=2)
    total_trackday_amount = models.DecimalField(max_digits=10, decimal_places=2)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    vehicle_image = models.ImageField(upload_to='vehicle_images/', null=True, blank=True)

    def __str__(self):
        return self.rider.username

from django.db import models
from django.contrib.auth.models import User  # Or your custom user model if you have one
from datetime import date

from django.db import models
from django.conf import settings
from datetime import date
from django.utils import timezone

class Bookingconfirmed(models.Model):
    STATUS_CHOICES = [
        ('upcoming', 'Upcoming'),
        ('in_progress', 'In Progress'),
        ('over', 'Over'),
        ('cancelled', 'Cancelled'),  # Added 'Cancelled' status
    ]

    CANCELLATION_STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]

    rider = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    bike = models.ForeignKey(Bike, on_delete=models.CASCADE)
    confirmed_date = models.DateTimeField(auto_now_add=True)
    trackday_date = models.DateField()
    number_of_trackdays = models.PositiveIntegerField(default=1, choices=[(1, '1 day'), (2, '2 days')])
    total_rental_amount = models.DecimalField(max_digits=10, decimal_places=2)
    total_trackday_fee = models.DecimalField(max_digits=10, decimal_places=2)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='upcoming')
    cancelled_date = models.DateTimeField(blank=True, null=True)  # Added field for cancelled date
    cancellation_status = models.CharField(max_length=15, choices=CANCELLATION_STATUS_CHOICES, default='pending')

    def save(self, *args, **kwargs):
        today = date.today()
        if self.trackday_date < today:
            self.status = 'over'
        elif self.trackday_date == today:
            self.status = 'in_progress'
        else:
            self.status = 'upcoming'

        super().save(*args, **kwargs)

    def cancel_booking(self):
        if self.status == 'upcoming' or self.status == 'in_progress':
            self.status = 'cancelled'
            self.cancelled_date = timezone.now()
            self.cancellation_status = 'approved'  # Set the cancellation status to 'approved'
            self.save()
            return True
        return False

    def __str__(self):
        return f'Booking for {self.rider.username} on {self.confirmed_date}'

    
from django.db import models

class PaymentRecord(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='payment_record')
    rider_name = models.CharField(max_length=100)
    trackday_date = models.DateField()
    number_of_trackdays = models.IntegerField()
    rental_amount = models.DecimalField(max_digits=10, decimal_places=2)
    amount = models.DecimalField(max_digits=10, decimal_places=2)  # New field for the payment amount
    confirmed_date = models.DateTimeField(null=True, blank=True)  # Field to store the confirmed date

    # Add any other fields as needed

    def __str__(self):
        return f"{self.user.username}'s Payment Record"
class UserProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    time = models.DurationField(null=True, blank=True)
    category = models.CharField(max_length=20, blank=True, null=True)
    lap_time_entered_at = models.DateTimeField(auto_now_add=True)
    total_race_time = models.CharField(max_length=100, default='00:00:00')  # Default value example

from django.db import models

class LapTimeEntry(models.Model):
    rider_name = models.CharField(max_length=100)
    lap_time = models.CharField(max_length=10)  # Assuming lap time format like mm:ss

    def __str__(self):
        return f'{self.rider_name} - {self.lap_time}'

from django.db import models

class RacingRider(models.Model):
    rider_name = models.CharField(max_length=100)
    email = models.EmailField()
    license_pdf = models.FileField(upload_to='license_pdfs/')  # Change the upload_to path as needed

    def __str__(self):
        return self.rider_name
    
from django.db import models
from .models import RacingRider

class CompanyRaceTime(models.Model):
    racer = models.ForeignKey(RacingRider, on_delete=models.CASCADE)
    race_time = models.CharField(max_length=10, blank=True, null=True)

    def __str__(self):
        return f"{self.racer.rider_name} - {self.race_time}"
    
