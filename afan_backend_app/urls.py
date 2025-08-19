from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from . import views
from .views import MemberViewSet, register_member, get_user_profile, KYCSubmissionView, KYCSubmissionView_agent
from django.urls import path


router = DefaultRouter()
router.register(r'members', MemberViewSet, basename='member')

urlpatterns = [
    path('register/', register_member, name='create_member'),
    # REMOVE THIS LINE:
    # path('login/', register_member, name='login_member'),

    # JWT login endpoint
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('user/', get_user_profile, name='get_user_profile'),
    # farmers membership registration related endpoints
    path('kyc/submit/', KYCSubmissionView_agent.as_view(), name='kyc-submit'),

    #payment related endpoints



]

