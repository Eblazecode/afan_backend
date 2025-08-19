import hashlib
import hmac
from venv import logger

from django.contrib.auth import authenticate
from django.shortcuts import render

# Create your views here.
from django.conf import settings


from rest_framework import viewsets, status, permissions
from rest_framework.authtoken.admin import User
from rest_framework.decorators import permission_classes, api_view
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
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Member  # your custom Member model


@api_view(['POST'])
@permission_classes([AllowAny])
def register_member(request):
    data = request.data
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    state = data.get('state')
    lga = data.get('lga')

    if not all([name, email, password, state, lga]):
        return Response({'error': 'Missing fields'}, status=status.HTTP_400_BAD_REQUEST)

    if Member.objects.filter(email=email).exists():
        return Response({'error': 'User already exists'}, status=status.HTTP_400_BAD_REQUEST)

    # Generate membership ID
    prefix = "AFAN"
    cleaned_state = re.sub(r'\W+', '', str(state)).upper()[:3].ljust(3, 'X')
    cleaned_lga = re.sub(r'\W+', '', str(lga)).upper()[:3].ljust(3, 'X')
    count = Member.objects.filter(state=state, lga=lga).count() + 1
    unique_code = str(count).zfill(5)
    gen_membership_id = f"{prefix}/{cleaned_state}/{cleaned_lga}/{unique_code}"

    if not re.match(r"^AFAN/[A-Z]{3}/[A-Z]{3}/\d{5}$", gen_membership_id):
        return Response({'error': 'Invalid membership ID format'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # Create member
    user = Member.objects.create(
        first_name=name,
        email=email,
        password=password,
        state=state,
        lga=lga,
        membership_id=gen_membership_id
    )

    refresh = RefreshToken.for_user(user)  # If using JWT with custom user, ensure your authentication backend supports it

    return Response({
        'refresh': str(refresh),
        'access': str(refresh.access_token),
        'user': {
            'id': user.id,
            'membership_id': user.membership_id,
            'name': user.first_name,
            'email': user.email,
            'state': user.state,
            'lga': user.lga
        }
    })


# login view for members
@api_view(['POST'])
@permission_classes([AllowAny])
def login_member(request):
    email = request.data.get('email')
    password = request.data.get('password')

    if email is None or password is None:
        return Response({'error': 'Email and password are required'}, status=400)

    user = authenticate(request, username=email, password=password)
    if user is not None:
        refresh = RefreshToken.for_user(user)
        return Response({
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': {
                'id': user.id,
                'email': user.email,
                'name': user.get_full_name(),  # or user.username or user.name
                'member_id':getattr(user,'member_id') or getattr(user.profile, 'member_id', None),  # Assuming you have a UserProfile model
            }
        })
    else:
        return Response({'error': 'Invalid email or password'}, status=401)



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
    permission_classes = [IsAuthenticated]
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




class KYCSubmissionView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]  # 👈 Accept file uploads

    def post(self, request):
        try:
            serializer = KYCSubmissionSerializer(data=request.data, context={'request': request})
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                # Optionally, you can update the user's kycStatus here
                user = request.user
                user.kycStatus = 'submitted'

                return Response({'message': 'KYC submitted successfully'}, status=status.HTTP_201_CREATED)
        except ValidationError as ve:
            return Response({'error': ve.detail}, status=status.HTTP_400_BAD_REQUEST)
        except ObjectDoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#