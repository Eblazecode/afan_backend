import uuid
from datetime import datetime

from django.contrib.auth.models import User
from django.db import models


import re
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.core.exceptions import ValidationError
from django.db import models
from django.conf import settings





# Create your models here.
import re
from django.db import models
from django.core.exceptions import ValidationError
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken

# Custom user model
from django.db import models
from django.contrib.auth.hashers import make_password

class Member(models.Model):
    email = models.EmailField(unique=True , default="email")
    first_name = models.CharField(max_length=100, default="first_name")
    last_name = models.CharField(max_length=100, blank=True, default="last_name")
    state = models.CharField(max_length=100, default="state")
    lga = models.CharField(max_length=100, default="lga")
    membership_id = models.CharField(max_length=50, unique=True, blank=True, null=False)
    password = models.CharField(max_length=128, default='password')  # store hashed password
    registration_date = models.DateTimeField(auto_now_add=True)
    kycStatus = models.CharField(default="not_submitted")  # KYC status
    paymentStatus = models.BooleanField(default=False)  # Payment status


    def save(self, *args, **kwargs):
        # Auto-generate membership ID if not set
        if not self.membership_id:
            self.membership_id = f"MEM-{uuid.uuid4().hex[:8].upper()}"

        if not self.id and self.password:  # hash password on creation
            self.password = make_password(self.password)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.first_name} {self.last_name or ''}"






from django.db import models
from django.db import models
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
import re

class KYCSubmission(models.Model):
    FARM_TYPES = [
        ('Crop Farming', 'Crop Farming'),
        ('Livestock Farming', 'Livestock Farming'),
        ('Poultry Farming', 'Poultry Farming'),
        ('Fish Farming', 'Fish Farming'),
        ('Mixed Farming', 'Mixed Farming'),
        ('Horticulture', 'Horticulture'),
        ('Forestry', 'Forestry'),
        ('Other', 'Other'),
    ]

    firstName = models.CharField(max_length=100)
    lastName = models.CharField(max_length=100)
    phoneNumber = models.CharField(max_length=11)
    nin = models.CharField(max_length=11, unique=True, blank=True, null=True, default=None)
    address = models.TextField()
    state = models.CharField(max_length=100)
    lga = models.CharField(max_length=100)
    farmType = models.CharField(max_length=50, choices=FARM_TYPES)
    farmSize = models.DecimalField(max_digits=10, decimal_places=2)
    yearsOfExperience = models.PositiveIntegerField()
    primaryCrops = models.CharField(max_length=255)
    farmLocation = models.TextField()
    passportPhoto = models.ImageField(upload_to='kyc/passport_photos/')
    submittedAt = models.DateTimeField(auto_now_add=True)
    membership_id = models.CharField(max_length=50, unique=True, blank=True, null=True)

    def __str__(self):
        return f"{self.firstName} {self.lastName} - {self.phoneNumber}"



    # display the membership ID to frontend
    def get_membership_id(self):
        return self.membership_id if self.membership_id else "Not Assigned"
    # -*- coding: utf-8 -*-

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    member_id = models.CharField(max_length=50, unique=True, null=True, blank=True)

    def __str__(self):
        return f"{self.user.username} Profile"

#

# fetch membership_id


