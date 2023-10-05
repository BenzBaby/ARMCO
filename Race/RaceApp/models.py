from django.db import models

from django.contrib.auth.models import AbstractUser,BaseUserManager

# Create your models here.

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None,role=None, **extra_fields):
        if not email:
            raise ValueError('User must have an email address')

       
        email= self.normalize_email(email)
        user = self.model(email=email,role=role, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, role='Admin', **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, role=role, **extra_fields)

class CustomUser(AbstractUser):
    ADMIN = 'Admin'
    RIDER = 'Rider'
    COMPANY = 'Company'
    ROLE_CHOICES = [
        (ADMIN, 'Admin'),
        (RIDER, 'Rider'),
        (COMPANY, 'Company'),
    ]

    # Fields for custom user roles
    role = models.CharField(max_length=15, choices=ROLE_CHOICES, default=RIDER)  # Default role for regular users
    forget_password_token = models.UUIDField(null=True, blank=True) #forgetpass
    email = models.EmailField(unique=True)
    objects = CustomUserManager()
    username = models.CharField(max_length=150, unique=True)
    
    # Define boolean fields for specific roles
    is_rider = models.BooleanField(default=True)
    is_company = models.BooleanField(default=False)

    def __str__(self):
        return self.email
  
  