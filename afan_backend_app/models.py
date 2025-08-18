from django.contrib.auth.models import User
from django.db import models



# Create your models here.
class Member(models.Model):
    firstname = models.CharField(max_length=100, default="")
    lastname = models.CharField(max_length=100, default="")
    phone_number = models.CharField(max_length=15, unique=True)
    state = models.CharField(max_length=100)
    lga = models.CharField(max_length=100)
    residential_address = models.TextField(max_length=100,default="")
    payment_status = models.BooleanField(default=False)
    registration_date = models.DateTimeField(auto_now_add=True)
    farming_type = models.CharField(max_length=100)
    farm_size = models.DecimalField(max_digits=10, decimal_places=2)
    farm_location = models.CharField(max_length=255)
    farming_years = models.IntegerField(default=0)
    farm_description = models.TextField(blank=True, null=True)
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)
    is_active = models.BooleanField(default=True)
    membership_id = models.CharField(max_length=50, unique=True, default="")


    def __str__(self):
        return self.full_name



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

    user = models.OneToOneField(User, on_delete=models.CASCADE, default="")
    firstName = models.CharField(max_length=100)
    lastName = models.CharField(max_length=100)
    phoneNumber = models.CharField(max_length=11)
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

    def save(self, *args, **kwargs):
        if not self.state or not self.lga:
            raise ValidationError("State and LGA must be provided to generate membership ID.")

        if not self.membership_id:
            prefix = "AFAN"

            # Safely process state and lga
            cleaned_state = re.sub(r'\W+', '', str(self.state)).upper()[:3].ljust(3, 'X')
            cleaned_lga = re.sub(r'\W+', '', str(self.lga)).upper()[:3].ljust(3, 'X')

            count = KYCSubmission.objects.filter(state=self.state, lga=self.lga).count() + 1
            unique_code = str(count).zfill(5)

            self.membership_id = f"{prefix}/{cleaned_state}/{cleaned_lga}/{unique_code}"

        if not re.match(r"^AFAN/[A-Z]{3}/[A-Z]{3}/\d{5}$", self.membership_id):
            raise ValidationError("membership_id must match format: AFAN/XXX/YYY/00001")

        # ✅ Save KYCSubmission
        super().save(*args, **kwargs)

        # ✅ Also update User profile with this membership_id
        if self.user:
            self.user.profile.member_id = self.membership_id  # If using UserProfile
            # OR if you added member_id directly to User via migration
            # self.user.member_id = self.membership_id
            self.user.save(update_fields=["member_id"])

    # display the membership ID to frontend
    def get_membership_id(self):
        return self.membership_id if self.membership_id else "Not Assigned"
    # -*- coding: utf-8 -*-
# payments model
class Payment(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_date = models.DateTimeField(auto_now_add=True)
    payment_status = models.CharField(max_length=20, choices=[('Pending', 'Pending'), ('Completed', 'Completed'), ('Failed', 'Failed')], default='Pending')
    transaction_id = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return f"Payment {self.transaction_id} - {self.user.username} - {self.amount} - {self.payment_status}"


