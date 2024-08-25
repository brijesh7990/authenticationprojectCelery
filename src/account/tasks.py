# accounts/tasks.py

from celery import shared_task
from django.core.mail import send_mail
from django.conf import settings


@shared_task
def send_password_reset_email(email, reset_link):
    email_body = f"""
    Hi,

    We received a request to reset your password. Please click the link below to reset it:

    {reset_link}

    If you did not request this change, please ignore this email.
    """

    send_mail(
        "Password Reset Request",
        email_body,
        settings.DEFAULT_FROM_EMAIL,
        [email],
        fail_silently=False,
    )
