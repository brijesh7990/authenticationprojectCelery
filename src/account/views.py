from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import User
from django.core.mail import send_mail
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str, force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView

from .tasks import send_password_reset_email
from .serializers import *

User = get_user_model()


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        "refresh": str(refresh),
        "access": str(refresh.access_token),
    }


class RegisterView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response(get_tokens_for_user(user), status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]
        user = authenticate(email=email, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)
            return Response(
                {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                }
            )

        return Response(
            {"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED
        )


class ChangePasswordView(generics.UpdateAPIView):
    serializer_class = ChangePasswordSerializer

    def get_object(self):
        return self.request.user

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        old_password = serializer.validated_data["old_password"]
        new_password = serializer.validated_data["new_password"]

        if not request.user.check_password(old_password):
            return Response(
                {"old_password": "Old password is incorrect"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        request.user.set_password(new_password)
        request.user.save()
        return Response({"detail": "Password updated successfully"})


class PasswordResetRequestView(generics.GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        if not User.objects.filter(email=email).exists():
            return Response(
                {"detail": "Email does not exist"}, status=status.HTTP_400_BAD_REQUEST
            )

        user = User.objects.get(email=email)
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        reset_link = (
            f"{request.build_absolute_uri('/api/password-reset/')}{uid}/{token}/"
        )

        # Call the Celery task to send the email
        send_password_reset_email.delay(email, reset_link)

        return Response(
            {"detail": "Password reset link sent"}, status=status.HTTP_200_OK
        )


class PasswordResetConfirmView(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer
    permission_classes = [AllowAny]

    def post(self, request, uidb64, token, *args, **kwargs):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            new_password = serializer.validated_data["new_password"]
            user.set_password(new_password)
            user.save()
            return Response(
                {"detail": "Password has been reset with the new password."},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"detail": "Invalid link or token."}, status=status.HTTP_400_BAD_REQUEST
            )
