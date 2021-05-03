from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, \
    PermissionsMixin
from django.core.validators import RegexValidator
import re


class UserManager(BaseUserManager):

    def create_user(self, email, password=None, **extra_fields):
        """Creates and saves a new user"""
        if not email:
            raise ValueError('User must have an email address')
        email_regex = r'^[a-zA-Z][a-zA-Z0-9._-]+@[a-zA-Z]+\.[a-zA-Z]{1,3}$'
        email_validator = bool(re.match(email_regex, email))
        if not email_validator:
            raise ValueError('Please type the correct email')
        user = self.model(email=self.normalize_email(email), **extra_fields)
        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self, email, password):
        """Create and saves a new super user"""
        user = self.create_user(email, password)
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self._db)

        return user


class User(AbstractBaseUser, PermissionsMixin):
    """Custom user model that supports using email instead of username"""
    phone_regex_validator = RegexValidator(regex=r"^+?[0-9]{5,12}$",
                                           message="The phone number format "
                                           "should be (+)998901234567. "
                                           "Up to 13 characters allowed")
    email = models.EmailField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    phone = models.CharField(max_length=13, unique=True,
                             validators=[phone_regex_validator])
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'
