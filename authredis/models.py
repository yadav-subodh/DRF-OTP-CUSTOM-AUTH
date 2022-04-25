from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from .managers import UserManager
import uuid

class User(AbstractBaseUser, PermissionsMixin):
    firstName = models.CharField(max_length=100)
    lastName = models.CharField(max_length=100, blank=True, null=True)
    dateOfBirth = models.DateTimeField(null=True)
    email = models.EmailField(max_length=100, unique=True)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    address = models.CharField(max_length=150)
    password = models.CharField(max_length=255, blank=True, null=True)
    createdAt = models.DateTimeField(auto_now_add=True)
    uid = models.CharField(max_length=100, default= str(uuid.uuid4()), unique=True)
    updatedAt = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return self.email
