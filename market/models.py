from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.
class Users(AbstractUser):
    customer_id = models.CharField(max_length=25, unique=True, blank=True)
    firstname = models.CharField(max_length=50, null=True, blank=True)
    lastname = models.CharField(max_length=50, null=True, blank=True)
    username = models.CharField(max_length=50, unique=True, null=True, blank=True)
    phone = models.CharField(max_length=15, null=True, blank=True)
    email = models.EmailField(unique=True)
    bio = models.TextField(null=True, blank=True)
    avatar = models.ImageField(upload_to='profile/', default='profile/avatar.png', null=True, blank=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']  
