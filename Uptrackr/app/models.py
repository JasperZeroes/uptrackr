from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django_countries.fields import CountryField
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User
from django.utils import timezone


class CustomUserManager(BaseUserManager):
    def create_user(self, username, email, full_name, password=None, country=None):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, full_name=full_name, country=country)
        user.set_password(password)
        user.save(using=self._db)
        return user

class CustomUser(AbstractBaseUser):
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(max_length=254, unique=True)
    full_name = models.CharField(max_length=254)
    country = CountryField(blank_label="(select country)")
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email', 'full_name']

    objects = CustomUserManager()

    def __str__(self):
        return self.username
 

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    activation_key = models.CharField(max_length=100)
    
    

class FreeTrialUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    start_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.username
    

class SubscriptionPayment(models.Model):
    user_name = models.CharField(max_length=100)
    event_name = models.CharField(max_length=100)
    created_at = models.DateTimeField(default=timezone.now)
    total_formatted = models.CharField(max_length=10)
    status = models.CharField(max_length=20)
    expiration_date = models.DateTimeField() 

    def __str__(self):
        return f'{self.user_name} - {self.event_name}'

    class Meta:
        verbose_name = 'Subscription Payment'
        verbose_name_plural = 'Subscription Payments'

