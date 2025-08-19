from .models import Member
from rest_framework import serializers
from .models import KYCSubmission
from rest_framework import serializers
class MemberSerializer(serializers.ModelSerializer):
    class Meta:
        model = Member
        fields = '__all__'
        read_only_fields = ['registration_date', 'is_active']

    def validate_email(self, value):
        if Member.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists.")
        return value

    def validate_phone_number(self, value):
        if Member.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError("Phone number already exists.")
        return value


from rest_framework import serializers
from .models import KYCSubmission

class KYCSubmissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = KYCSubmission
        fields = [
            'firstName',
            'lastName',
            'phoneNumber',
            'address',
            'state',
            'lga',
            'farmType',
            'farmSize',
            'yearsOfExperience',
            'primaryCrops',
            'farmLocation',
            'passportPhoto',
            'membership_id',
        ]

    def create(self, validated_data):
        user = self.context['request'].user  # Get the authenticated user

        # Ensure only one KYCSubmission per user
        if KYCSubmission.objects.filter(user=user).exists():
            raise serializers.ValidationError("KYC already submitted.")

        return KYCSubmission.objects.create(user=user, **validated_data)
