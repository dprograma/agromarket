from django.urls import path
from .views import UserSignup, UserSignin, UpdateProfile, ForgotPassword, UserSignOut, ActivationUser, UserDelete, InitializationRequest, ResetPassword, GetUser

urlpatterns = [
    path('signup/', UserSignup.as_view(), name='signup'),
    path('signin/', UserSignin.as_view(), name='signin'),
    path('profile/', UpdateProfile.as_view(), name='profile'),
    path('forgot-password/', ForgotPassword.as_view(), name='forgot-password'),
    path('reset-password/', ResetPassword.as_view(), name='reset_password'),
    path('signout/', UserSignOut.as_view(), name='signout'),
    path('activate/<str:uidb64>/<str:token>', ActivationUser.as_view(), name='activate'),
    path('delete/', UserDelete.as_view(), name='delete'),
    path('initialize-request/', InitializationRequest.as_view(), name='initialize_request'),
    path('getuser/', GetUser.as_view(), name='get_user'),
]
