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

    def __str__(self):
        return f"{self.user.username}'s Lap Time: {self.time}, Category: {self.category}"


# models.py
from django.db import models

class Trackday(models.Model):
    date = models.DateField()
    # Add other fields as needed
