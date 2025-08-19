import hashlib
import hmac
from venv import logger

from django.contrib.auth import authenticate
from django.shortcuts import render

# Create your views here.

from rest_framework import viewsets, status, permissions
from rest_framework.authtoken.admin import User
from rest_framework.decorators import permission_classes, api_view
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken

from .models import  Member
from .serializers import MemberSerializer
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import KYCSubmission
from .serializers import KYCSubmissionSerializer




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


@api_view(['POST'])
@permission_classes([AllowAny])
def register_member(request):
    print("Incoming data:", request.data)

    name = request.data.get('name')
    email = request.data.get('email')
    password = request.data.get('password')

    if not all([name, email, password]):
        return Response({'error': 'Missing fields'}, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(username=email).exists():
        return Response({'error': 'User already exists'}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.create_user(
        username=email,
        email=email,
        password=password,
        first_name=name
    )

    refresh = RefreshToken.for_user(user)

    return Response({
        'refresh': str(refresh),
        'access': str(refresh.access_token),
        'user': {
            'id': user.id,
            'name': user.first_name,
            'email': user.email,
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
                return Response({'message': 'KYC submitted successfully'}, status=status.HTTP_201_CREATED)
        except ValidationError as ve:
            return Response({'error': ve.detail}, status=status.HTTP_400_BAD_REQUEST)
        except ObjectDoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# views.py
import requests
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse, HttpResponse
import json

@csrf_exempt
def initiate_payment(request):
    if request.method == 'POST':
     try :
        data = json.loads(request.body)
        email = data.get('email')
        amount = int(data.get('amount')) * 100  # convert to kobo
        gateway = data.get('gateway', 'paystack')

        if gateway == 'paystack':
            url = 'https://api.paystack.co/transaction/initialize'
            headers = {
                'Authorization': f'Bearer {settings.PAYSTACK_SECRET_KEY}',
                'Content-Type': 'application/json',
            }
            payload = {
                'email': email,
                'amount': amount,
                'callback_url': f"{settings.FRONTEND_URL}/payment-callback",
            }
            response = requests.post(url, json=payload, headers=headers)
            resp_data = response.json()
            if resp_data.get('status'):
                return JsonResponse({'payment_url': resp_data['data']['authorization_url']})
            return JsonResponse({'error': 'Paystack error'}, status=400)

        elif gateway == 'flutterwave':
            url = 'https://api.flutterwave.com/v3/payments'
            headers = {
                'Authorization': f'Bearer {settings.FLUTTERWAVE_SECRET_KEY}',
                'Content-Type': 'application/json',
            }
            payload = {
                "tx_ref": f"TX-{email}-{amount}",
                "amount": str(amount / 100),
                "currency": "NGN",
                "redirect_url": f"{settings.FRONTEND_URL}/payment-callback",
                "customer": {
                    "email": email,
                },
                "customizations": {
                    "title": "Fan Payment",
                    "description": "Pay for your ticket"
                }
            }
            response = requests.post(url, json=payload, headers=headers)
            resp_data = response.json()
            if resp_data.get('status') == 'success':
                return JsonResponse({'payment_url': resp_data['data']['link']})
            return JsonResponse({'error': 'Flutterwave error'}, status=400)
     except Exception as e:
         logger.error(~f"Payment initiation failed: {str(e)}")
         return JsonResponse({'error': 'Payment initiation failed'}, status=500)

    return JsonResponse({'error': 'Invalid request'}, status=400)



@csrf_exempt
def verify_payment(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        reference = data.get('reference')
        gateway = data.get('gateway', 'paystack')

        if gateway == 'paystack':
            url = f"https://api.paystack.co/transaction/verify/{reference}"
            headers = {
                'Authorization': f'Bearer {settings.PAYSTACK_SECRET_KEY}',
            }
            response = requests.get(url, headers=headers)
            resp_data = response.json()
            if resp_data.get('status') and resp_data['data']['status'] == 'success':
                # Update user/payment record
                # Example:
                # User.objects.filter(email=resp_data['data']['customer']['email']).update(payment_status='paid')
                return JsonResponse({'success': True})
            return JsonResponse({'error': 'Verification failed'}, status=400)

        elif gateway == 'flutterwave':
            url = f"https://api.flutterwave.com/v3/transactions/{reference}/verify"
            headers = {
                'Authorization': f'Bearer {settings.FLUTTERWAVE_SECRET_KEY}',
            }
            response = requests.get(url, headers=headers)
            resp_data = response.json()
            if resp_data.get('status') == 'success' and resp_data['data']['status'] == 'successful':
                # Update user/payment
                return JsonResponse({'success': True})
            return JsonResponse({'error': 'Verification failed'}, status=400)

    return JsonResponse({'error': 'Invalid request'}, status=400)

# views.py

@csrf_exempt
def paystack_webhook(request):
    if request.method == 'POST':
        payload = request.body
        received_signature = request.headers.get('x-paystack-signature')

        # Validate signature
        expected_signature = hmac.new(
            key=bytes(settings.PAYSTACK_SECRET_KEY, 'utf-8'),
            msg=payload,
            digestmod=hashlib.sha512
        ).hexdigest()

        if received_signature != expected_signature:
            return HttpResponse(status=400)

        event = json.loads(payload)
        event_type = event.get('event')
        data = event.get('data', {})

        if event_type == 'charge.success' and data.get('status') == 'success':
            email = data['customer']['email']
            reference = data['reference']
            amount = data['amount'] / 100  # Convert from kobo to naira

            # Update payment status in your DB
            # Example:
            # User.objects.filter(email=email).update(payment_status='paid')
            # Or create Payment model and update there

            return JsonResponse({'status': 'success'}, status=200)

    return HttpResponse(status=400)

