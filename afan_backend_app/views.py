import hashlib
import hmac
import uuid
from urllib import request
from venv import logger

from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from django.contrib.sites import requests
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.shortcuts import render, get_object_or_404

# Create your views here.
from django.conf import settings

import logging

from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from rest_framework import viewsets, status, permissions
from rest_framework.authtoken.admin import User
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken

from .models import Member, AgentMember, AdminUser
from .serializers import MemberSerializer
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import KYCSubmission
from .serializers import KYCSubmissionSerializer

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings
from django.contrib.auth import get_user_model


class MemberViewSet(viewsets.ModelViewSet):
    queryset = Member.objects.all()
    serializer_class = MemberSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)



User = get_user_model()
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken


import re
from django.core.exceptions import ValidationError
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny



def gen_membership_id_func(state, lga):
    import re
    prefix = "AFAN"
    cleaned_state = re.sub(r'\W+', '', str(state)).upper()[:3].ljust(3, 'X')
    cleaned_lga = re.sub(r'\W+', '', str(lga)).upper()[:3].ljust(3, 'X')
    count = Member.objects.filter(state=state, lga=lga).count() + 1
    unique_code = str(count).zfill(5)

    gen_membership_id = f"{prefix}/{cleaned_state}/{cleaned_lga}/{unique_code}"

    # validate format
    if not re.match(r"^AFAN/[A-Z]{3}/[A-Z]{3}/\d{5}$", gen_membership_id):
        raise ValueError("Invalid membership ID format")

    return gen_membership_id  # ✅ return the value


@api_view(['POST'])
@permission_classes([AllowAny])
def register_member(request):
    data = request.data
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    state = data.get('state')
    lga = data.get('lga')


    print("Received data:", data)  # Debugging line to check received data
    if not all([name, email, password, state, lga]):
        return Response({'error': 'Missing fields'}, status=400)

    # if  email exists
    if Member.objects.filter(email=email).exists():
        return Response({'error': 'user already already exists'}, status=400)

    # split full name into first/last
    parts = name.strip().split(" ", 1)
    first_name = parts[0]
    last_name = parts[1] if len(parts) > 1 else ""

    import re
    prefix = "AFAN"
    cleaned_state = re.sub(r'\W+', '', str(state)).upper()[:3].ljust(3, 'X')
    cleaned_lga = re.sub(r'\W+', '', str(lga)).upper()[:3].ljust(3, 'X')
    count = Member.objects.filter(state=state, lga=lga).count() + 1
    unique_code = str(count).zfill(5)

    gen_membership_id = f"{prefix}/{cleaned_state}/{cleaned_lga}/{unique_code}"

    # validate format
    if not re.match(r"^AFAN/[A-Z]{3}/[A-Z]{3}/\d{5}$", gen_membership_id):
        raise ValueError("Invalid membership ID format")

    member = Member.objects.create(
        email=email,
        first_name=first_name,
        last_name=last_name,
        state=state,
        lga=lga,
        password=password,
        membership_id= gen_membership_id,  # your custom function

    )

    refresh = RefreshToken.for_user(member)
    return Response({
        "user": {
            "id": member.id,
            "name": f"{member.first_name} {member.last_name}".strip(),
            "email": member.email,
            "membership_id": member.membership_id,
            "state": member.state,
            "lga": member.lga,
            "kycStatus": member.kycStatus,
            "paymentStatus": member.paymentStatus,

        },
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }, status=201)


from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.db import transaction
from django.db.utils import IntegrityError
import re

from .models import AgentMember, Member


@api_view(['POST'])
@permission_classes([AllowAny])
def register_agent(request):
    data = request.data
    print("Received data:", data)  # Debugging

    required_fields = ['name', 'email', 'password', 'state', 'lga', 'ward', 'nin', 'phoneNumber', 'DOB', 'education', 'gender']
    if not all(data.get(field) for field in required_fields):
        return Response({'error': 'Missing required fields'}, status=400)

    name = data.get('name').strip()
    email = data.get('email').strip().lower()
    password = data.get('password')
    state = data.get('state').strip()
    lga = data.get('lga').strip()
    ward = data.get('ward').strip()
    nin = data.get('nin').strip()
    phoneNumber = data.get('phoneNumber').strip()
    DOB = data.get('DOB')
    education = data.get('education').strip()
    gender = data.get('gender').strip()

    # Check if email, phone, or NIN already exist
    if Member.objects.filter(email=email).exists():
        return Response({'error': 'User email already exists'}, status=400)

    if AgentMember.objects.filter(phoneNumber=phoneNumber).exists():
        return Response({'error': 'Phone number already exists'}, status=400)

    if AgentMember.objects.filter(nin=nin).exists():
        return Response({'error': 'NIN already exists'}, status=400)

    # Check suspended or pending agents
    existing_agent = AgentMember.objects.filter(nin=nin, approval_status__in=['suspended', 'pending']).first()
    if existing_agent:
        return Response({'error': f'Agent account is {existing_agent.approval_status}. Please contact support.'}, status=400)

    # Split full name
    parts = name.split(" ", 1)
    first_name = parts[0]
    last_name = parts[1] if len(parts) > 1 else ""

    prefix = "AFAN/AGT"
    cleaned_state = re.sub(r'\W+', '', str(state)).upper()[:3].ljust(3, 'X')
    cleaned_lga = re.sub(r'\W+', '', str(lga)).upper()[:3].ljust(3, 'X')

    # Generate unique agent_id safely using transaction
    for attempt in range(5):
        try:
            with transaction.atomic():
                count = AgentMember.objects.filter(state=state, lga=lga).count() + 1
                unique_code = str(count).zfill(5)
                agent_id = f"{prefix}/{cleaned_state}/{cleaned_lga}/{unique_code}"

                # Ensure unique ID
                if AgentMember.objects.filter(agent_id=agent_id).exists():
                    continue

                agentmember = AgentMember.objects.create(
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    state=state,
                    lga=lga,
                    password=password,
                    agent_id=agent_id,
                    ward=ward,
                    nin=nin,
                    phoneNumber=phoneNumber,
                    DOB=DOB,
                    gender=gender,
                    education=education,
                )
                break
        except IntegrityError:
            continue
    else:
        return Response({'error': 'Could not generate unique Agent ID, please try again.'}, status=500)

    # JWT Token
    refresh = RefreshToken.for_user(agentmember)

    return Response({
        "message": "Agent registered successfully!",
        "user": {
            "id": agentmember.id,
            "name": f"{agentmember.first_name} {agentmember.last_name}".strip(),
            "email": agentmember.email,
            "membership_id": agentmember.agent_id,
            "state": agentmember.state,
            "lga": agentmember.lga,
            "ward": agentmember.ward,
            "phoneNumber": agentmember.phoneNumber,
            "nin": agentmember.nin,
            "DOB": agentmember.DOB,
            "education": agentmember.education,
            "gender": agentmember.gender,
            "registration_date": agentmember.registration_date,
            "kycStatus": agentmember.kycStatus,
            "paymentStatus": agentmember.paymentStatus,
        },
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }, status=201)



from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.contrib.auth.hashers import check_password
from rest_framework_simplejwt.tokens import RefreshToken
from .models import AgentMember



@api_view(['POST'])
@permission_classes([AllowAny])
def login_agent(request):
    email = request.data.get('email')
    password = request.data.get('password')

    if not email or not password:
        return Response({'error': 'Email and password are required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        agent = AgentMember.objects.get(email=email)
    except AgentMember.DoesNotExist:
        return Response({'error': 'Invalid email or password'}, status=status.HTTP_401_UNAUTHORIZED)

    # 🔐 Check password
    # Debugging: check password
    is_valid_password = check_password(password, agent.password)
    logger.debug(f"Password check for {email}: {is_valid_password}")

    if not is_valid_password:
        logger.warning(f"Invalid password attempt for email: {email}")
        return Response({'error': 'Invalid email or password'}, status=401)


    # ✅ Generate token only if approved
    refresh = RefreshToken.for_user(agent)

    return Response({
        "user": {
            "id": agent.id,
            "name": f"{agent.first_name} {agent.last_name}".strip(),
            "email": agent.email,
            "agent_id": agent.agent_id,
            "state": agent.state,
            "lga": agent.lga,
            "role": "agent",
            "kycStatus": agent.kycStatus,
            "paymentStatus": agent.paymentStatus,
            "transaction_id": agent.transaction_id,
            "approval_status": agent.approval_status,
        },
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }, status=status.HTTP_200_OK)




@api_view(['POST'])
@permission_classes([AllowAny])
def login_admin(request):
    email = request.data.get('email')
    password = request.data.get('password')

    if not email or not password:
        return Response({'error': 'Email and password are required'}, status=400)

    try:
        admin = AdminUser.objects.get(email=email)  # query by email
    except AdminUser.DoesNotExist:
        return Response({'error': 'Invalid email or password'}, status=401)

    if not check_password(password, admin.password):
        return Response({'error': 'Invalid email or password'}, status=401)

    refresh = RefreshToken.for_user(admin)

    return Response({
        "user": {
            "id": admin.id,
            "name": f"{admin.first_name} {admin.last_name}".strip(),
            "email": admin.email,
            "admin_id": admin.adminID, # keep it for reference
            "role": "admin",
            "lga": admin.lga,
            "state": admin.state,

        },
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }, status=200)


from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import check_password
from .models import Member   # import your Member model





from django.contrib.auth.hashers import check_password
from rest_framework.response import Response
from rest_framework.decorators import api_view
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Member

# Configure logging
@api_view(['POST'])
@permission_classes([AllowAny])
def login_member(request):
    email = request.data.get('email')
    password = request.data.get('password')

    # Log incoming data (avoid logging plain passwords in production)
    logger.info(f"Login attempt for email: {email}")

    if email is None or password is None:
        logger.warning("Email or password missing in request")
        return Response({'error': 'Email and password are required'}, status=400)

    try:
        member = Member.objects.get(email=email)
    except Member.DoesNotExist:
        logger.warning(f"Member not found for email: {email}")
        return Response({'error': 'Invalid email or password'}, status=401)

    # Debugging: check password
    is_valid_password = check_password(password, member.password)
    logger.debug(f"Password check for {email}: {is_valid_password}")

    if not is_valid_password:
        logger.warning(f"Invalid password attempt for email: {email}")
        return Response({'error': 'Invalid email or password'}, status=401)

    refresh = RefreshToken.for_user(member)

    logger.info(f"Login successful for {email}, membership_id: {member.membership_id}")

    return Response({
        "user": {
            "id": member.id,
            "name": f"{member.first_name} {member.last_name}".strip(),
            "email": member.email,
            "membership_id": member.membership_id,
            "state": member.state,
            "lga": member.lga,
            "role": "member",
            "kycStatus": member.kycStatus,
            "paymentStatus": member.paymentStatus,
            "transaction_id": member.transaction_id,


        },
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }, status=200)


from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def get_user_profile(request):
    user = request.user
    return Response({
        "id": user.id,
        "email": user.email,
        "name": user.get_full_name(),
        "is_admin": user.is_staff,  # or user.is_superuser depending on your logic
        "kycStatus": getattr(user, "kycStatus", "not_submitted"),
        "paymentStatus": getattr(user, "paymentStatus", "pending"),
    })


# Note: The above code assumes that the User model has fields like kycStatus and paymentStatus.
# If these fields are not present, you may need to adjust the code accordingly.



from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.exceptions import ValidationError
from django.core.exceptions import ObjectDoesNotExist
from .serializers import KYCSubmissionSerializer


from rest_framework.parsers import MultiPartParser, FormParser

class KYCSubmissionView_agent(APIView):
    parser_classes = [MultiPartParser, FormParser]  # 👈 Accept file uploads

    def post(self, request):
        try:
            serializer = KYCSubmissionSerializer(data=request.data, context={'request': request})
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                return Response({'message': 'KYC submitted successfully'}, status=status.HTTP_201_CREATED)
        except ValidationError as ve:
            return Response({'error': ve.detail}, status=status.HTTP_400_BAD_REQUEST)
        except ObjectDoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import KYCSubmission  # make sure your model is imported


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.parsers import MultiPartParser, FormParser
from .models import KYCSubmission

from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.parsers import MultiPartParser, FormParser


class KYCSubmissionView(APIView):
    permission_classes = [AllowAny]  # 👈 anyone can access
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request, *args, **kwargs):
        try:
            data = request.data
            files = request.FILES

            # Debugging received payloads
            print("====== DEBUG START ======")
            print("Raw request data:", data)
            print("Raw request files:", files)
            print("Membership ID received:", data.get('membership_id'))
            print("Passport photo received:", files.get('passportPhoto'))
            print("====== DEBUG END ======")

            # Extract fields
            first_name = data.get('firstName')
            last_name = data.get('lastName')
            phone_number = data.get('phoneNumber')
            gender = data.get('gender')
            DOB = data.get('DOB')
            nin = data.get('nin')
            address = data.get('address')
            state = data.get('state')
            lga = data.get('lga')
            farmingSeason = data.get('farmingSeason')
            farmingCommunity = data.get('farmingCommunity')
            ward = data.get('ward')
            education = data.get('education')
            secondary_commodity = data.get('secondaryCommodity')
            farm_type = data.get('farmType')
            farm_size = data.get('farmSize')
            years_of_experience = data.get('yearsOfExperience')
            primary_commodity = data.get('primaryCommodity')
            farm_location = data.get('farmLocation')
            passport_photo = files.get('passportPhoto')
            membership_id = data.get('membership_id')

            # Extra check for membership_id being readonly
            if not membership_id:
                print("⚠️ Membership ID is missing from request!")
            else:
                print("✅ Membership ID included:", membership_id)

                # ✅ Upload passport photo to Supabase if provided
                passport_url = None
            if passport_photo:
                ext = passport_photo.name.split('.')[-1]
                file_name = f"{membership_id}_passport.{ext}"
                passport_url = upload_passport(passport_photo, file_name)

            # Create record
            kyc = KYCSubmission.objects.create(
                firstName=first_name,
                lastName=last_name,
                gender = gender,
                DOB = DOB,
                farmingSeason = farmingSeason,
                farmingCommunity = farmingCommunity,
                ward = ward,
                education = education,
                secondaryCrops = secondary_commodity,
                phoneNumber=phone_number,
                nin=nin,
                address=address,
                state=state,
                lga=lga,
                farmType=farm_type,
                farmSize=farm_size,
                yearsOfExperience=years_of_experience,
                primaryCrops=primary_commodity,
                farmLocation=farm_location,
                passportPhoto=passport_url if passport_url else None,
                membership_id=membership_id,
                kycStatus="approved",  # default status
            )
            # update member record where membership_id matches
            member = Member.objects.get(membership_id=membership_id)
            member.kycStatus = "approved"
            member.save()


            return Response(
                {"message": "Farmer record submission successful", "id": kyc.membership_id},
                status=status.HTTP_201_CREATED
            )

        except Exception as e:
            print("❌ ERROR in KYCSubmissionView:", str(e))
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

# verify payment
# views.py



# AGENT KYC SUBMISSION VIEW FOR FARMERS REGISTERED BY AGENTS


from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status



from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated

import os
from supabase import create_client
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.parsers import MultiPartParser, FormParser

# 🔑 Environment variables (set in Heroku Config Vars)
SUPABASE_URL = settings.SUPABASE_URL
SUPABASE_ANON_KEY = settings.SUPABASE_ANON_KEY
SUPABASE_SERVICE_ROLE_KEY = settings.SUPABASE_SERVICE_ROLE_KEY
SUPABASE_BUCKET_NAME = settings.SUPABASE_BUCKET_NAME

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)


def upload_passport(file_obj: InMemoryUploadedFile, folder: str = "kyc/passport_photos"):
    try:
        # Generate a unique filename
        file_ext = file_obj.name.split(".")[-1]
        file_name = f"{folder}/{uuid.uuid4()}.{file_ext}"

        # Upload bytes
        res = supabase.storage.from_(SUPABASE_BUCKET_NAME).upload(file_name, file_obj.read(), {
            "content-type": file_obj.content_type
        })

        # Get public URL
        return supabase.storage.from_(SUPABASE_BUCKET_NAME).get_public_url(file_name)
    except Exception as e:
        print(f"❌ Supabase upload error: {e}")
        return None

class KYCSubmissionView_agent(APIView):
    permission_classes = [AllowAny]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request, *args, **kwargs):
        try:
            data = request.data
            files = request.FILES

            print("====== DEBUG START ======")
            print("📩 Raw request data:", data)
            print("📸 Raw request files:", files)
            print("👉 AGENT ID received:", data.get('agent_id'))
            print("====== DEBUG END ======")

            # Extract fields
            first_name = data.get('firstName')
            last_name = data.get('lastName')
            gender = data.get('gender')
            DOB = data.get('DOB')
            phone_number = data.get('phoneNumber')
            agent_id = data.get('agent_id')
            nin = data.get('nin')
            farmingSeason = data.get('farmingSeason')
            farmingCommunity = data.get('farmingCommunity')
            ward = data.get('ward')
            education = data.get('education')
            secondary_commodity = data.get('secondaryCommodity')
            address = data.get('address')
            state = data.get('state')
            lga = data.get('lga')
            farm_type = data.get('farmType')
            farm_size = data.get('farmSize')
            years_of_experience = data.get('yearsOfExperience')
            primary_commodity = data.get('primaryCommodity')
            farm_location = data.get('farmLocation')
            passport_photo = files.get('passportPhoto')

            if not agent_id:
                return Response({"error": "agent_id is required"}, status=400)

            # Validate agent exists
            try:
                agent = AgentMember.objects.get(agent_id=agent_id)
            except AgentMember.DoesNotExist:
                return Response({"error": "Agent not found"}, status=404)

            # Generate membership_id
            membership_id = gen_membership_id_func(state, lga)

            # ✅ Upload passport photo to Supabase if provided
            passport_url = None
            if passport_photo:
                ext = passport_photo.name.split('.')[-1]
                file_name = f"{membership_id}_passport.{ext}"
                passport_url = upload_passport(passport_photo, file_name)

            # ✅ Create KYC record
            kyc = KYCSubmission.objects.create(
                firstName=first_name,
                lastName=last_name,
                phoneNumber=phone_number,
                gender=gender,
                DOB=DOB,
                farmingSeason=farmingSeason,
                farmingCommunity=farmingCommunity,
                ward=ward,
                education=education,
                secondaryCrops=secondary_commodity,
                nin=nin,
                address=address,
                state=state,
                lga=lga,
                farmType=farm_type,
                farmSize=farm_size,
                yearsOfExperience=years_of_experience,
                primaryCrops=primary_commodity,
                farmLocation=farm_location,
                passportPhoto=passport_url if passport_url else None,
                membership_id=membership_id,
                agent_id=agent_id,
                kycStatus="approved",
            )

            # ✅ Create linked Member (email only required here)
            email = f"{membership_id.lower()}@afannigeria.com"
            Member.objects.create(
                first_name=first_name,
                last_name=last_name,
                state=state,
                lga=lga,
                membership_id=membership_id,
                kycStatus="approved",
                paymentStatus="not_paid",
                password="farmer123",
                email=email,
            )

            return Response(
                {
                    "message": "Farmer record submission successful",
                    "id": kyc.membership_id,
                    "passportPhoto": passport_url,
                },
                status=status.HTTP_201_CREATED
            )

        except Exception as e:
            print("❌ ERROR in KYCSubmissionView:", str(e))
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view
from django.conf import settings
import requests
from .models import Member



from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.conf import settings
import requests
from .models import Member

import requests
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.conf import settings
from .models import Member


@api_view(["POST"])
@permission_classes([AllowAny])
def verify_payment(request, reference):
    # Get membership_id from POST body
    membership_id = request.data.get("membership_id")

    if not membership_id:
        logger.warning(f"Payment verification failed: missing membership_id for reference {reference}")
        return Response(
            {"status": "error", "message": "Missing membership ID"},
            status=400
        )

    try:
        # Call Paystack API
        headers = {"Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}"}
        url = f"https://api.paystack.co/transaction/verify/{reference}"
        response = requests.get(url, headers=headers).json()

        # Log the full response for debugging
        logger.info(f"Paystack verification response for {reference}: {response}")

        if response.get("status") and response["data"]["status"] == "success":
            try:
                member = Member.objects.get(membership_id=membership_id)
                member.paymentStatus = "paid"
                member.transaction_id = reference
                member.save()

                # update kycSubmission payment status if exists matching membership_id
                try:
                    kyc = KYCSubmission.objects.get(membership_id=membership_id)
                    kyc.paymentStatus = "paid"
                    kyc.transaction_id = reference
                    kyc.save()
                except KYCSubmission.DoesNotExist:
                    logger.warning(f"No KYCSubmission found for membership_id {membership_id}")

                logger.info(f"Payment verified successfully for member {membership_id}")

                return Response({
                    "status": "success",
                    "data": {
                        "transaction_id": reference,
                        "amount": response["data"]["amount"] / 100,
                        "date": response["data"]["paid_at"],
                        "member": {
                            "name": f"{member.first_name} {member.last_name}",
                            "email": member.email,
                            "membership_id": member.membership_id,
                            "farmType": member.farmType,

                        }
                    }
                })

            except Member.DoesNotExist:
                logger.error(f"Member not found for membership_id {membership_id}")
                return Response(
                    {"status": "error", "message": "Member not found"},
                    status=404
                )

        # If Paystack status not success
        logger.warning(f"Payment not successful for reference {reference}: {response}")
        return Response({"status": "error", "message": "Payment not successful"}, status=400)

    except Exception as e:
        logger.exception(f"Error verifying payment for reference {reference}: {str(e)}")
        return Response({"status": "error", "message": str(e)}, status=500)



from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.conf import settings
import requests
import logging
from .models import Member, KYCSubmission

logger = logging.getLogger(__name__)



from rest_framework.response import Response
import requests
from django.conf import settings
from .models import Member, KYCSubmission

@api_view(["POST"])
@permission_classes([AllowAny])
def verify_agent_payment(request, reference):
    try:
        # 🔑 Call Paystack API to verify
        headers = {"Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}"}
        url = f"https://api.paystack.co/transaction/verify/{reference}"
        response = requests.get(url, headers=headers).json()

        if response.get("status") and response["data"]["status"] == "success":
            # ✅ Pull membership_id from metadata
            metadata = response["data"].get("metadata", {})
            membership_id = metadata.get("membership_id")

            if not membership_id:
                return Response({"status": "error", "message": "Missing membership_id in metadata"}, status=400)

            # 🔎 Update Member record
            try:
                member = Member.objects.get(membership_id=membership_id)
                member.paymentStatus = "paid"
                member.transaction_id = reference
                member.save()

                # 🔎 Update KYCSubmission if exists
                try:
                    kyc = KYCSubmission.objects.get(membership_id=membership_id)
                    if hasattr(kyc, "paymentStatus"):
                        kyc.paymentStatus = "paid"
                    if hasattr(kyc, "transaction_id"):
                        kyc.transaction_id = reference
                    kyc.save()
                except KYCSubmission.DoesNotExist:
                    kyc = None  # no kyc for this member

                return Response({
                    "status": "success",
                    "data": {
                        "transaction_id": reference,
                        "amount": response["data"]["amount"] / 100,
                        "date": response["data"]["paid_at"],
                        "member": {
                            "name": f"{member.first_name} {member.last_name}",
                            "membership_id": member.membership_id,
                            "farmType": getattr(kyc, "farmType", None) if kyc else None,
                        }
                    }
                })
            except Member.DoesNotExist:
                return Response({"status": "error", "message": "Member not found"}, status=404)

        return Response({"status": "error", "message": "Payment not successful"}, status=400)

    except Exception as e:
        return Response({"status": "error", "message": str(e)}, status=500)



from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.contrib.auth.hashers import make_password


from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.core.mail import send_mail
from django.conf import settings

@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password(request):
    email = request.data.get('email')
    if not email:
        return Response({'error': 'Email is required'}, status=400)

    try:
        # check member table or agent member table


        member = Member.objects.get(email=email)
    except Member.DoesNotExist:
        return Response({'error': 'No account with this email'}, status=404)

    token = member.set_reset_token()
    reset_link = f"https://www.afannigeria.com/reset-password/{member.id}/{token}/"

    send_mail(
        'Reset Your AFAN Password',
        f'Click here to reset your password: {reset_link}',
        settings.DEFAULT_FROM_EMAIL,
        [email],
        fail_silently=False,
    )
    return Response({'message': 'Password reset link sent to your email'}, status=200)


from django.contrib.auth.hashers import make_password
from django.utils import timezone

@api_view(['POST'])
@permission_classes([AllowAny])
def reset_password(request, user_id, token):
    password = request.data.get('password')
    if not password:
        return Response({'error': 'Password is required'}, status=400)

    try:
        member = Member.objects.get(id=user_id, reset_token=token)
    except Member.DoesNotExist:
        return Response({'error': 'Invalid token or user'}, status=404)

    if not member.reset_token_expiry or member.reset_token_expiry < timezone.now():
        return Response({'error': 'Token expired'}, status=400)

    member.password = make_password(password)
    member.reset_token = None
    member.reset_token_expiry = None
    member.save()

    return Response({'message': 'Password reset successful'}, status=200)



from django.core.mail import send_mail
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.utils import timezone
from django.contrib.auth.hashers import make_password
from .models import AgentMember


@api_view(['POST'])
@permission_classes([AllowAny])
def agent_forgot_password(request):
    email = request.data.get('email')
    if not email:
        return Response({'error': 'Email is required'}, status=400)

    try:
        agent = AgentMember.objects.get(email=email)
    except AgentMember.DoesNotExist:
        return Response({'error': 'No account found with this email'}, status=404)

    token = agent.set_reset_token()
    agent_name = f"{agent.first_name} {agent.last_name}".strip()
    reset_link = f"https://www.afannigeria.com/agentreset-password/{agent.id}/{token}/"

    send_mail(
        'Reset Your AFAN Agent Password',
        f'Hi {agent_name},\n\nClick the link below to reset your password:\n{reset_link}\n\nThis link will expire in 1 hour.',
        settings.DEFAULT_FROM_EMAIL,
        [email],
        fail_silently=False,
    )

    return Response({'message': 'Password reset link sent to your email.'}, status=200)



from django.contrib.auth.hashers import make_password
from django.utils import timezone

@api_view(['POST'])
@permission_classes([AllowAny])
def agent_reset_password(request, user_id, token):
    password = request.data.get('password')
    if not password:
        return Response({'error': 'Password is required'}, status=400)

    try:
        agent= AgentMember.objects.get(id=user_id, reset_token=token)
    except AgentMember.DoesNotExist:
        return Response({'error': 'Invalid token or user'}, status=404)

    if not agent.reset_token_expiry or agent.reset_token_expiry < timezone.now():
        return Response({'error': 'Token expired'}, status=400)

    agent.password = make_password(password)
    agent.reset_token = None
    agent.reset_token_expiry = None
    agent.save()

    return Response({'message': 'Password reset successful'}, status=200)


from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from .models import KYCSubmission
from .serializers import KYCSubmissionSerializer

@api_view(["GET"])
@permission_classes([AllowAny])  # Anyone can call this
def get_farmers_by_agent(request, agent_id):
    farmers = KYCSubmission.objects.filter(agent_id=agent_id).order_by("submittedAt")

    # Convert queryset into dicts that match frontend fields
    farmer_list = [
        {
            "membership_id": f.membership_id,
            "name": f.firstName + " " + f.lastName,
            "email": f.membership.email if hasattr(f, 'membership') else "",
            "phoneNumber": f.phoneNumber,
            "status": f.kycStatus,
            "registeredAt": f.submittedAt,   # ✅ rename submittedAt -> registeredAt
            "paymentStatus": f.paymentStatus,
            "farmType": f.farmType,
            "farmSize": f.farmSize,
            "yearsOfExperience": f.yearsOfExperience,
            "primaryCrops": f.primaryCrops,
            "farmLocation": f.farmLocation,
            "state": f.state,
            "lga": f.lga,

        }
        for f in farmers
    ]

    return Response({
        "data": farmer_list,
        "count": len(farmer_list)
    })

# AGENT PAY FOR FARMER
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from .models import KYCSubmission, Member  # adjust import if needed


from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.utils.timezone import localtime

@api_view(["GET"])
@permission_classes([AllowAny])
def agent_get_payment_receipt(request, membership_id):
    try:
        # ✅ Get KYCSubmission
        kyc = KYCSubmission.objects.get(membership_id=membership_id)

        # ✅ Try to get Member too (if you have such a model)
        member = None
        try:
            from .models import Member  # adjust import if needed
            member = Member.objects.get(membership_id=membership_id)
        except Exception:
            pass  # not fatal if Member doesn’t exist

        # ✅ Safely extract values
        transaction_id = getattr(kyc, "transaction_id", f"TXN-{membership_id}")
        amount = 5000
        payment_date = getattr(kyc, "payment_date", None)
        if payment_date:
            payment_date = localtime(payment_date).strftime("%Y-%m-%d %H:%M:%S")

        # ✅ Build response
        receipt_data = {
            "transaction_id": transaction_id,
            "amount": amount,
            "date": payment_date,
            "paymentStatus": getattr(kyc, "paymentStatus", "unpaid"),
            "member": {
                "name": f"{getattr(kyc, 'firstName', '')} {getattr(kyc, 'lastName', '')}".strip(),
                "membership_id": getattr(kyc, "membership_id", ""),
                "phoneNumber": getattr(kyc, "phoneNumber", ""),
                "farmType": getattr(kyc, "farmType", ""),
                "email": getattr(member, "email", None) if member else None,
            }
        }

        return Response({"status": "success", "data": receipt_data}, status=200)

    except KYCSubmission.DoesNotExist:
        return Response({"status": "error", "message": "Farmer not found"}, status=404)
    except Exception as e:
        return Response({"status": "error", "message": str(e)}, status=500)


import requests
from rest_framework.response import Response
from rest_framework.decorators import api_view
from django.conf import settings

@api_view(["POST"])
@permission_classes([AllowAny])
def initiate_agent_payment(request):
    membership_id = request.data.get("membership_id")
    email = request.data.get("email")
    amount = request.data.get("amount")  # pass in kobo, e.g. 5000 NGN = 500000

    print("Request data:", request.data)

    if not membership_id or not email or not amount:
        return Response({"status": "error", "message": "Missing fields"}, status=400)

    headers = {"Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}"}
    payload = {
        "email": email,
        "amount": amount,
        "callback_url": "https://www.afannigeria.com/agent-paymentcallback",
        "metadata": {
            "membership_id": membership_id
        }
    }

    url = "https://api.paystack.co/transaction/initialize"
    r = requests.post(url, headers=headers, json=payload)
    res = r.json()

    if res.get("status"):
        return Response({
            "status": "success",
            "authorization_url": res["data"]["authorization_url"],
            "reference": res["data"]["reference"]
        })
    else:
        return Response({"status": "error", "message": res.get("message")}, status=400)




import requests
from django.conf import settings
from django.shortcuts import redirect
from django.http import JsonResponse

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from django.http import JsonResponse
import requests
from django.conf import settings
import json

@api_view(["POST"])
@permission_classes([AllowAny])
def agent_payment_callback(request):
    data = request.data
    reference = data.get("reference")
    membership_id = data.get("membership_id")

    if not reference or not membership_id:
        return JsonResponse({"status": "error", "message": "Missing reference or membership_id"}, status=400)

    headers = {"Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}"}
    response = requests.get(
        f"https://api.paystack.co/transaction/verify/{reference}",
        headers=headers
    )
    res_data = response.json()

    if res_data.get("status") and res_data["data"]["status"] == "success":
        try:
            member = Member.objects.get(membership_id=membership_id)
            member.paymentStatus = "paid"
            member.transaction_id = reference
            member.save()
        except Member.DoesNotExist:
            pass

        try:
            kyc = KYCSubmission.objects.get(membership_id=membership_id)
            kyc.paymentStatus = "paid"
            kyc.transaction_id = reference
            kyc.save()
        except KYCSubmission.DoesNotExist:
            pass

        return JsonResponse({"status": "success", "message": "Payment verified"})
    else:
        return JsonResponse({"status": "error", "message": "Verification failed"}, status=400)


# ADMIN DASHBOARD SECTION

@api_view(['POST'])
@permission_classes([AllowAny])
def admin_register(request):
        data = request.data
        name = data.get('name')
        email = data.get('email')
        password = data.get('password')
        state = data.get('state')
        lga = data.get('lga')

        print("Received data:", data)  # Debugging line to check received data
        if not all([name, email, password, state, lga]):
            return Response({'error': 'Missing fields'}, status=400)

        # if  email exists
        if AdminUser.objects.filter(email=email).exists():
            return Response({'error': 'user already already exists'}, status=400)

        # split full name into first/last
        parts = name.strip().split(" ", 1)
        first_name = parts[0]
        last_name = parts[1] if len(parts) > 1 else ""

        import re
        prefix = "AFAN/ADM"
        cleaned_state = re.sub(r'\W+', '', str(state)).upper()[:3].ljust(3, 'X')
        cleaned_lga = re.sub(r'\W+', '', str(lga)).upper()[:3].ljust(3, 'X')
        count = Member.objects.filter(state=state, lga=lga).count() + 1
        unique_code = str(count).zfill(5)

        gen_membership_id = f"{prefix}/{cleaned_state}/{cleaned_lga}/{unique_code}"

        # validate format
        if not re.match(r"^AFAN/ADM/[A-Z]{3}/[A-Z]{3}/\d{5}$", gen_membership_id):
            raise ValueError("Invalid membership ID format")

        admin = AdminUser.objects.create(
            email=email,
            first_name=first_name,
            last_name=last_name,
            state=state,
            lga=lga,
            password=password,
            adminID=gen_membership_id,  # your custom function

        )

        refresh = RefreshToken.for_user(admin)
        return Response({
            "user": {
                "id": admin.id,
                "name": f"{admin.first_name} {admin.last_name}".strip(),
                "email": admin.email,
                "adminID": admin.adminID,
                "state": admin.state,
                "lga": admin.lga,


            },
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }, status=201)




def AdminLogin(request):

    return JsonResponse({"message": "Admin Login - To be implemented"}, status=200)

def AdminDashboard(request):
    # fetch all members records from KYCSubmission model
    Allmembers = Member.objects.all()



    return JsonResponse({"message": "Admin Dashboard farmers - To be implemented"}, status=200)

# fetch all farmers from the KYCSubmission table
import os
from django.conf import settings
import os
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.conf import settings

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.conf import settings
from supabase import create_client
import os


@api_view(['GET'])
@permission_classes([AllowAny])
def admin_fetch_all_farmers(request):
    farmers = KYCSubmission.objects.all().order_by('-submittedAt')
    farmer_list = []

    # ✅ Default fallback (Supabase public URL for default.png)
    default_passport_url = supabase.storage.from_(SUPABASE_BUCKET_NAME).get_public_url(
        "kyc/passport_photos/default.png"
    )

    for f in farmers:
        passport_url = f.passportPhoto if f.passportPhoto else default_passport_url

        #

        farmer_list.append({
            "membership_id": f.membership_id,
            "name": f"{f.firstName} {f.lastName}",
            "phoneNumber": f.phoneNumber,
            "status": f.kycStatus,
            "registeredAt": f.submittedAt,
            "paymentStatus": f.paymentStatus,
            "farmType": f.farmType,
            "farmSize": f.farmSize,
            "yearsOfExperience": f.yearsOfExperience,
            "farmLocation": f.farmLocation,
            "state": f.state,
            "gender":f.gender,
            "DOB": f.DOB,
            "lga": f.lga,
            "position":f.position,
            "primaryCrops":f.primaryCrops,
            "secondaryCrops":f.secondaryCrops,
            "ward":f.ward,
            "passportPhoto": passport_url,
            "submissiondate": f.submittedAt,
            "agent_id": f.agent_id,
        })

    return Response({
        "data": farmer_list,
        "count": len(farmer_list)
    })



@api_view(['GET'])
@permission_classes([AllowAny])
def admin_fetch_all_agents(request):
    agents = AgentMember.objects.all().order_by('-registration_date')
    agents_list = []

    # ✅ Default fallback (Supabase public URL for default.png)
    default_passport_url = supabase.storage.from_(SUPABASE_BUCKET_NAME).get_public_url(
        "kyc/passport_photos/default.png"
    )
    # passport_url = a.passportPhoto if a.passportPhoto else default_passport_url

    for a in agents:

        #

        agents_list.append({
            "agent_id": a.agent_id,
            "name": f"{a.first_name} {a.last_name}",
            "phoneNumber": a.phoneNumber,
            "state": a.state,
            "lga": a.lga,
            "ward": a.ward,
            "registration_date": a.registration_date,
            "email": a.email,
            "DOB": a.DOB,
            "gender":a.gender,
            "education": a.education,
            "nin": a.nin,
            "status":a.approval_status,



        })
    #    "passportPhoto": passport_url,
    return Response({
        "data": agents_list,
        "count": len(agents_list)
    })


# views.py
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
  # adjust model name
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from .models import KYCSubmission
import logging

# ✅ setup logger
logger = logging.getLogger(__name__)

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from .models import KYCSubmission

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from .models import KYCSubmission

@api_view(['GET'])
@permission_classes([AllowAny])
def verify_farmer(request, membership_id):
    try:
        farmer = KYCSubmission.objects.get(membership_id=membership_id)

        return Response({
            "status": "verified",
            "farmer": {
                "id": farmer.membership_id,
                "name": f"{farmer.firstName} {farmer.lastName}",
                "state": farmer.state,
                "lga": farmer.lga,
                "farmType": farmer.farmType,
                "farmSize": farmer.farmSize,
                "phoneNumber": farmer.phoneNumber,
                "yearsOfExperience": farmer.yearsOfExperience,
                # ✅ FIXED: no .url
                "passportPhoto": farmer.passportPhoto if farmer.passportPhoto else None,
                "produce": farmer.primaryCrops,
            }
        }, status=200)

    except KYCSubmission.DoesNotExist:
        return Response(
            {"status": "invalid", "message": "Farmer not found"},
            status=404
        )
    except Exception as e:
        # ✅ Add debug logging for unexpected errors
        return Response(
            {"status": "error", "message": f"Unexpected error: {str(e)}"},
            status=500
        )




import json
import logging
from django.http import JsonResponse
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404
from .models import KYCSubmission

# Setup logger
logger = logging.getLogger(__name__)


from django.http import JsonResponse
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404
from .models import KYCSubmission
import json

@method_decorator(csrf_exempt, name='dispatch')
class FarmerDetailView(View):

    def get(self, request, membership_id):
        """Fetch a farmer by membership_id with debug logs"""
        print("\n====== DEBUG: FETCH FARMER START ======")
        print(f"📩 Incoming membership_id: {membership_id}")

        try:
            farmer = get_object_or_404(KYCSubmission, membership_id=membership_id)
            print(f"✅ Farmer found: {farmer.firstName} {farmer.lastName} ({farmer.membership_id})")
        except Exception as e:
            print(f"❌ ERROR fetching farmer: {e}")
            print("====== DEBUG: FETCH FARMER END ======\n")
            return JsonResponse({"error": "Farmer not found"}, status=404)

        data = {
            "firstName": farmer.firstName,
            "lastName": farmer.lastName,
            "phoneNumber": farmer.phoneNumber,
            "nin": farmer.nin,
            "education": farmer.education,
            "gender": farmer.gender,
            "DOB": farmer.DOB,
            "address": farmer.address,
            "state": farmer.state,
            "lga": farmer.lga,
            "ward": farmer.ward,
            "farmingCommunity": farmer.farmingCommunity,
            "farmingSeason": farmer.farmingSeason,
            "farmType": farmer.farmType,
            "farmSize": str(farmer.farmSize),
            "yearsOfExperience": farmer.yearsOfExperience,
            "primaryCrops": farmer.primaryCrops,
            "secondaryCrops": farmer.secondaryCrops,
            "farmLocation": farmer.farmLocation,
            "passportPhoto": farmer.passportPhoto,
            "membership_id": farmer.membership_id,
        }

        print("📤 Farmer data prepared successfully")
        print("====== DEBUG: FETCH FARMER END ======\n")

        return JsonResponse(data, safe=False, status=200)

    def put(self, request, membership_id):
        """Update a farmer record with debug logs"""
        print("\n====== DEBUG: UPDATE FARMER START ======")
        print(f"📩 Incoming membership_id: {membership_id}")

        try:
            farmer = get_object_or_404(KYCSubmission, membership_id=membership_id)
            print(f"✅ Farmer found for update: {farmer.firstName} {farmer.lastName}")
        except Exception as e:
            print(f"❌ ERROR fetching farmer for update: {e}")
            print("====== DEBUG: UPDATE FARMER END ======\n")
            return JsonResponse({"error": "Farmer not found"}, status=404)

        try:
            body = json.loads(request.body.decode('utf-8'))
            print(f"🧾 Incoming JSON body: {body}")
        except json.JSONDecodeError as e:
            print(f"❌ JSON decode error: {e}")
            print("====== DEBUG: UPDATE FARMER END ======\n")
            return JsonResponse({"error": "Invalid JSON"}, status=400)

        updated_fields = []
        for field, value in body.items():
            if hasattr(farmer, field):
                setattr(farmer, field, value)
                updated_fields.append(field)

        farmer.save()
        print(f"✅ Updated fields: {updated_fields}")
        print("====== DEBUG: UPDATE FARMER END ======\n")

        return JsonResponse({"message": "Farmer record updated successfully!"}, status=200)






@api_view(['POST'])
@permission_classes([AllowAny])
def approve_agent(request, id):
    """✅ Approve an agent with debugging"""
    print("\n🟢 [DEBUG] Approve Agent Endpoint Hit")
    print("👉 Incoming ID:", id)
    print("👉 Headers:", dict(request.headers))
    print("👉 Authenticated user:", request.user)
    print("👉 Method:", request.method)

    try:
        agent = AgentMember.objects.get(agent_id=id)
        print("✅ Agent found:", agent.agent_id, agent.first_name)

        agent.approval_status = "Approved"
        agent.save()

        print("🟢 Agent approval status updated successfully")

        return Response(
            {"message": f"Agent {agent.first_name} approved successfully"},
            status=status.HTTP_200_OK
        )
    except AgentMember.DoesNotExist:
        print("❌ ERROR: Agent not found for ID:", id)
        return Response({"error": "Agent not found"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        print("🚨 Unexpected error:", str(e))
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



@api_view(['POST'])
@permission_classes([AllowAny])
def suspend_agent(request, id):
    """🚫 Suspend an agent with debugging"""
    print("\n🟡 [DEBUG] Suspend Agent Endpoint Hit")
    print("👉 Incoming ID:", id)
    print("👉 Headers:", dict(request.headers))
    print("👉 Authenticated user:", request.user)
    print("👉 Method:", request.method)

    try:
        agent = AgentMember.objects.get(agent_id=id)
        print("✅ Agent found:", agent.agent_id, agent.first_name)

        agent.approval_status = "Suspended"
        agent.save()

        print("🟡 Agent approval status set to Suspended")

        return Response(
            {"message": f"Agent {agent.first_name} suspended successfully"},
            status=status.HTTP_200_OK
        )
    except AgentMember.DoesNotExist:
        print("❌ ERROR: Agent not found for ID:", id)
        return Response({"error": "Agent not found"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        print("🚨 Unexpected error:", str(e))
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



@api_view(['DELETE'])
@permission_classes([AllowAny])
def delete_agent(request, id):
    """🗑️ Delete an agent with debugging"""
    print("\n🔴 [DEBUG] Delete Agent Endpoint Hit")
    print("👉 Incoming ID:", id)
    print("👉 Headers:", dict(request.headers))
    print("👉 Authenticated user:", request.user)
    print("👉 Method:", request.method)

    try:
        agent = AgentMember.objects.get(agent_id=id)
        name = agent.first_name
        agent.delete()
        print(f"🗑️ Agent {name} deleted successfully")

        return Response(
            {"message": f"Agent {name} deleted successfully"},
            status=status.HTTP_200_OK
        )
    except AgentMember.DoesNotExist:
        print("❌ ERROR: Agent not found for ID:", id)
        return Response({"error": "Agent not found"}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        print("🚨 Unexpected error:", str(e))
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
