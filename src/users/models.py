from django.db import models
from django.contrib.auth.models import AbstractUser


# Create your models here.
class User(AbstractUser):
    name = models.CharField(max_length=255)
    phone = models.CharField(max_length=255)
    profile_picture = models.ImageField(upload_to='images/')
    email = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    username = models.CharField(max_length=255, blank=True, null=True)
    # last_login = None
    # is_superuser = None
    # is_staff = None

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
