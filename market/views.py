import json
import random
import time
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import generics, permissions
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from django.conf import settings
from django.template.loader import render_to_string
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import (
    OutstandingToken,
    BlacklistedToken,
)
from rest_framework_simplejwt.exceptions import TokenError
from django.middleware.csrf import get_token
from .serializers import UsersSerializer, GetUserSerializer
from .models import Users
from .sendmail import SendMail
from .permissions import IsOwner


# Initialization request to get csrf_token
class InitializationRequest(APIView):
    def get(self, request, *args, **kwargs):
        csrf_token = get_token(request)
        return Response(
            {"status": "success", "response": csrf_token}, status=status.HTTP_200_OK
        )


# Call a user record
class GetUser(generics.ListAPIView):
    """View class to retrieve merchant profile"""

    serializer_class = GetUserSerializer
    permission_classes = []

    def get(self, request, *args, **kwargs):
        try:
            user = Users.objects.get(id=request.user.id)
        except Users.DoesNotExist:
            user = None

        if user is not None:
            serializer = self.get_serializer(user)
            return Response(
                {"status": "success", "response": serializer.data},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"status": "error", "response": "User not found"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class UserSignup(generics.CreateAPIView):
    """View class to process user signup"""

    permission_classes = []
    serializer_class = UsersSerializer
    activation_email = "market/activation_email.html"

    def post(self, request, *args, **kwargs) -> Response | None:
        """Create a user account and send out an activation email to user email"""
        email = request.data.get("email")
        password = request.data.get("password")
        try:
            user = Users.objects.get(email=email)
        except Users.DoesNotExist:
            user = None

        if user is None:
            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid():
                serializer.save(is_active=False, password=make_password(password))
                user = Users.objects.get(email=email)
                # Send email confirmation
                current_site = settings.CLIENT_SITE
                mail_subject = "Activate your account"
                message = render_to_string(
                    self.activation_email,
                    {
                        "user": user,
                        "domain": current_site,
                        "uid": urlsafe_base64_encode(force_bytes(user.id)),
                        "token": default_token_generator.make_token(user),
                    },
                )
                to_email = email
                email = SendMail(mail_subject, message, to_email)
                return Response(
                    {"status": "success", "response": "User created successfully"},
                    status=status.HTTP_201_CREATED,
                )
            else:
                return Response(
                    {"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST
                )

        else:
            return Response(
                {
                    "status": "error",
                    "response": f"This email <em>{email}</em> is already registered.",
                },
                status=status.HTTP_200_OK,
            )


class ActivationUser(APIView):
    """View class to activate user account"""

    def get(self, request, uidb64, token) -> Response:
        """get method to retrieve uid and token from user's email"""
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = Users.objects.get(id=uid)
        except (TypeError, ValueError, OverflowError, Users.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            return Response(
                {
                    "status": "success",
                    "response": "Your account has been activated successfully. You can now log in.",
                },
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"status": "error", "response": "Invalid activation link."},
                status=status.HTTP_400_BAD_REQUEST,
            )


class UserSignin(APIView):
    """View class to process user login"""

    queryset = Users.objects.all()
    permission_classes = []
    serializer = GetUserSerializer

    def post(self, request) -> Response:
        email = request.data.get("email", "")
        password = request.data.get("password", "")

        user = authenticate(email=email, password=password)
        if user is not None:
            # Create a new token for this user
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            serialized = self.serializer(user, data=request.data)
            if serialized.is_valid():
                current_user = serialized.data
                return Response(
                    {
                        "status": "success",
                        "response": {
                            "user": current_user,
                            "access_token": access_token,
                            "refresh_token": str(refresh),
                        },
                    },
                    status=status.HTTP_200_OK,
                )
            else:
                return Response(
                    {"status": "error", "response": "Invalid credentials"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
        else:
            return Response(
                {"status": "error", "response": "Invalid credentials111"},
                status=status.HTTP_401_UNAUTHORIZED,
            )


class UpdateProfile(generics.RetrieveUpdateAPIView):
    """View class to update user profile"""

    serializer_class = UsersSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Users.objects.filter(id=self.request.user.id)

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs) -> Response:        
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            self.perform_update(serializer)
            return Response(
                {"status": "success", "response": serializer.data},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"status": "error", "response": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )


class ForgotPassword(APIView):
    """View class to process user forgotten password"""

    permission_classes = []
    reset_email = "market/password_reset_email.html"

    def post(self, request):
        email = request.data.get("email", "")
        try:
            user = Users.objects.get(email=email)
        except Users.DoesNotExist:
            user = None

        if user is not None:
            current_site = settings.CLIENT_SITE
            mail_subject = "Reset your password"
            message = render_to_string(
                self.reset_email,
                {
                    "user": user,
                    "domain": current_site,
                    "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                    "token": default_token_generator.make_token(user),
                },
            )
            to_email = email
            email = SendMail(mail_subject, message, to_email)
            email.send()
            return Response(
                {
                    "status": "success",
                    "response": f"You will receive an email with instructions to reset your password.",
                },
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"status": "error", "response": "Incorrect email supplied."},
                status=status.HTTP_400_BAD_REQUEST,
            )


class ResetPassword(generics.RetrieveUpdateAPIView):
    permission_classes = []
    serializer_class = UsersSerializer
    queryset = Users.objects.all()

    def post(self, request):
        uidb64 = request.data.get("uid")
        token = request.data.get("token")
        password = request.data.get("password")
        hashed_password = make_password(password=password)
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = Users.objects.get(id=uid)
        except (TypeError, ValueError, OverflowError, Users.DoesNotExist):
            user = None
        data = {"password": hashed_password}
        if user is not None and default_token_generator.check_token(user, token):
            serializer = self.get_serializer(user, data=data, partial=True)
            if serializer.is_valid():
                self.perform_update(serializer)
                return Response(
                    {
                        "status": "success",
                        "response": "Password reset was successful",
                    },
                    status=status.HTTP_200_OK,
                )
        else:
            return Response(
                {
                    "status": "error",
                    "response": "Invalid activation link",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )


class UserSignOut(generics.DestroyAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def destroy(self, request, *args, **kwargs):

        try:
            # Find all refresh tokens for the user
            tokens = OutstandingToken.objects.filter(
                user_id=request.user.id, token__isnull=False
            )
            for token in tokens:
                # Blacklist each token
                BlacklistedToken.objects.get_or_create(token=token)
                # Optionally, delete the outstanding token if you want to clean up
                token.delete()

            return Response(
                {"status": "success", "response": "Successfully logged out"},
                status=status.HTTP_200_OK,
            )
        except (
            TokenError,
            OutstandingToken.DoesNotExist,
            BlacklistedToken.DoesNotExist,
        ):
            return Response(
                {"status": "error", "response": "Invalid token"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class UserDelete(generics.DestroyAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def destroy(self, request, *args, **kwargs):
        try:
            # Delete all outstanding tokens
            tokens = OutstandingToken.objects.filter(user_id=request.user.id)
            for token in tokens:
                token.blacklist()
        except TokenError as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        # Delete user
        request.user.delete()

        return Response(
            {"status": "success", "response": "User account has been deleted"},
            status=status.HTTP_200_OK,
        )
