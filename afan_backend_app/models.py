import uuid
from datetime import datetime, timezone, timedelta

from django.contrib.auth.models import User
from django.db import models


import re
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.core.exceptions import ValidationError
from django.db import models
from django.conf import settings
from django.utils import timezone
from datetime import timedelta


class MemberManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Email is required")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)  # properly hashes
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_agent", True)
        return self.create_user(email, password, **extra_fields)
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
    paymentStatus = models.CharField(default="not_paid")  # Payment status
    transaction_id = models.CharField(max_length=100, blank=True, null=True)

    reset_token = models.CharField(max_length=255, blank=True, null=True)
    reset_token_expiry = models.DateTimeField(blank=True, null=True)

    def set_reset_token(self):
        import uuid
        self.reset_token = str(uuid.uuid4())
        self.reset_token_expiry = timezone.now() + timedelta(hours=1)
        self.save()
        return self.reset_token

    # Required fields for AbstractBaseUser
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = MemberManager()



    def save(self, *args, **kwargs):
        # Auto-generate membership ID if not set
        if not self.membership_id:
            self.membership_id = f"MEM-{uuid.uuid4().hex[:8].upper()}"

        if not self.id and self.password:  # hash password on creation
            self.password = make_password(self.password)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.first_name} {self.last_name or ''}  {self.email}"


class AgentMember(models.Model):
    email = models.EmailField(unique=True , default="email")
    first_name = models.CharField(max_length=100, default="first_name")
    last_name = models.CharField(max_length=100, blank=True, default="last_name")
    state = models.CharField(max_length=100, default="state")
    lga = models.CharField(max_length=100, default="lga")
    agent_id = models.CharField(max_length=50, unique=True, blank=True, null=False)
    password = models.CharField(max_length=128, default='password')  # store hashed password
    registration_date = models.DateTimeField(auto_now_add=True)
    kycStatus = models.CharField(default="not_submitted")  # KYC status
    paymentStatus = models.CharField(default="not_paid")  # Payment status
    transaction_id = models.CharField(max_length=100, blank=True, null=True)

    # Required fields for AbstractBaseUser
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = MemberManager()


    def save(self, *args, **kwargs):
        # Auto-generate membership ID if not set
        if not self.agent_id:
            self.membership_id = f"AFANAGT-{uuid.uuid4().hex[:8].upper()}"

        if not self.id and self.password:  # hash password on creation
            self.password = make_password(self.password)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.first_name} {self.last_name or ''}  {self.email}"





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
    agent_id = models.CharField(max_length=50, blank=True, null=True)
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
    kycStatus = models.CharField(max_length=20, default='not_submitted')  # KYC status
    paymentStatus = models.CharField(max_length=20, default='not_paid')  # Payment status
    transaction_id = models.CharField(max_length=100, blank=True, null=True)

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

# Admin registration
class AdminUser(models.Model):
    first_name = models.CharField(max_length=100)
    adminID = models.CharField(max_length=50, unique=True, blank=True, null=False)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128)
    state = models.CharField(max_length=100, default="state")
    lga = models.CharField(max_length=100, default="lga")
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    is_superadmin = models.BooleanField(default=False)


    def __str__(self):
        return self.user.username


