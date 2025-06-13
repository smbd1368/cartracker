from django.urls import path

from . import views
from core.settings import ENABLE_PROTECTED_VIEW
urlpatterns = [
    path('agn-users/', views.AgnUserListView.as_view(), name='agn-user-list'),
    path("login/", views.UserLoginAPIView.as_view(), name="login"),
    path('verify-token/', views.VerifyTokenAPIView.as_view(), name='verify-token'),
    path('refresh/', views.RefreshTokenAPIView.as_view(), name='refresh_token'),
    path('pax/', views.PaxUserRegisterView.as_view(), name='register_pax_user'),
    path('pax/profile/', views.PaxUserReteriveView.as_view(), name='get-profile-pax-user'),
    path('otp/', views.SendOTPView.as_view(), name='send_otp'),
    path('password-change/otp', views.PasswordChangeWithOTPView.as_view(), name='password-change-with-otp'),
    path('paxuser/image/', views.PaxUserImageUpdateAPIView.as_view(), name='paxuser-image-update'),
    path('change-username/', views.ChangeUsernameAPIView.as_view(), name='change-username'),
    path('password-change/token', views.ChangePasswordWithTokenAPIView.as_view(), name='password-change-with-token'),
    path('language/', views.ChangeLanguageJustPackUserAPIView.as_view(), name='password-language-for-user'),
    path('pax-user/locations/', views.PaxUserLocationAPIView.as_view(), name='pax-user-locations'),
    
]

if ENABLE_PROTECTED_VIEW:
    urlpatterns += [
        # path('protected/', views.ProtectedView.as_view(), name='protected-view'),
    ]