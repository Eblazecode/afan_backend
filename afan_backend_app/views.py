import hashlib
import hmac
from urllib import request
from venv import logger

from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from django.contrib.sites import requests
from django.shortcuts import render

# Create your views here.
from django.conf import settings

import logging
from rest_framework import viewsets, status, permissions
from rest_framework.authtoken.admin import User
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken

from .models import Member
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
            "transaction_id": member.transaction_id if hasattr(member, 'transaction_id') else None,

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
from rest_framework.response import Response
from rest_framework import status
from .models import KYCSubmission

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
            nin = data.get('nin')
            address = data.get('address')
            state = data.get('state')
            lga = data.get('lga')
            farm_type = data.get('farmType')
            farm_size = data.get('farmSize')
            years_of_experience = data.get('yearsOfExperience')
            primary_crops = data.get('primaryCrops')
            farm_location = data.get('farmLocation')
            passport_photo = files.get('passportPhoto')
            membership_id = data.get('membership_id')

            # Extra check for membership_id being readonly
            if not membership_id:
                print("⚠️ Membership ID is missing from request!")
            else:
                print("✅ Membership ID included:", membership_id)

            # Create record
            kyc = KYCSubmission.objects.create(
                firstName=first_name,
                lastName=last_name,
                phoneNumber=phone_number,
                nin=nin,
                address=address,
                state=state,
                lga=lga,
                farmType=farm_type,
                farmSize=farm_size,
                yearsOfExperience=years_of_experience,
                primaryCrops=primary_crops,
                farmLocation=farm_location,
                passportPhoto=passport_photo,
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


from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.contrib.auth.hashers import make_password


@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password(request):
    email = request.data.get('email')
    if not email:
        return Response({'error': 'Email is required'}, status=400)

    try:
        member = Member.objects.get(email=email)
    except Member.DoesNotExist:
        return Response({'error': 'No account with this email'}, status=404)

    token = default_token_generator.make_token(member)
    reset_link = f"https://www.afannigeria.com/reset-password/{member.id}/{token}/"

    send_mail(
        'Reset Your AFAN Password',
        f'Click here to reset your password: {reset_link}',
        'support@fan.ng',
        [email],
        fail_silently=False,
    )
    return Response({'message': 'Password reset link sent to your email'}, status=200)


@api_view(['POST'])
@permission_classes([AllowAny])
def reset_password(request, user_id, token):
    password = request.data.get('password')
    if not password:
        return Response({'error': 'Password is required'}, status=400)

    try:
        member = Member.objects.get(id=user_id)
    except Member.DoesNotExist:
        return Response({'error': 'Invalid user'}, status=404)

    if not default_token_generator.check_token(member, token):
        return Response({'error': 'Invalid or expired token'}, status=400)

    member.password = make_password(password)
    member.save()
    return Response({'message': 'Password reset successful'}, status=200)
