from django.db import models
from django.contrib.auth.models import AbstractUser

from base.models import BaseModel

# Create your models here.


class User(BaseModel, AbstractUser):
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=150, unique=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["username"]
