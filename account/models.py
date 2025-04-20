from django.db import models
from django.contrib.auth.models import AbstractBaseUser
from datetime import timedelta
from django.utils import timezone
import re


class UserManager(models.Manager):
    def create_user(self, phone, username=None, email=None, password=None, **extra_fields):
        phone = self.normalize_phone(phone)
        if not email and not username:
            user = self.model(phone=phone, username=None, email=None, **extra_fields)
        elif email or username:
            if not email:
                username = self.normalize_username(username)
                user = self.model(phone=phone, username=username, email=None, **extra_fields)
            elif not username:
                email = self.normalize_email(email)
                user = self.model(phone=phone, username=None, email=email, **extra_fields)
            elif username and email:
                username, email = self.normalize_username(username), self.normalize_email(email)
                user = self.model(phone=phone, username=username, email=email, **extra_fields)

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, phone, username=None, email=None, password=None, **extra_fields):
        extra_fields.setdefault('is_admin', True)
        return self.create_user(phone, username, email, password, **extra_fields)

    def get_by_natural_key(self, username):
        return self.get(**{self.model.USERNAME_FIELD: username})

    async def aget_by_natural_key(self, username):
        return await self.aget(**{self.model.USERNAME_FIELD: username})

    @staticmethod
    def normalize_phone(phone: str):
        if not phone:
            raise ValueError('users must have a phone number')
        phone = UserManager.convert_persian_digits_to_english(phone)
        phone = re.sub(r'\D', '', phone)
        if len(phone) == 11 and phone.startswith('09'):
            return phone
        else:
            raise ValueError('InValid Phone Number')

    @staticmethod
    def convert_persian_digits_to_english(phone: str) -> str:
        persian_english_digits = dict({
            '۰': '0', '۱': '1', '۲': '2', '۳': '3', '۴': '4', '۵': '5', '۶': '6', '۷': '7', '۸': '8', '۹': '9'
        })
        for persian, english in persian_english_digits.items():
            phone = phone.replace(persian, english)
        return phone

    @staticmethod
    def normalize_username(username: str):
        username = username.strip().lower()
        result = ""
        last_character = ""
        allowed_character = 'abcdefghijklmnopqrstuvwxyz0123456789'

        for i in username:
            if i in allowed_character:
                result += i
                last_character = i
            elif i in (' ', '-', '_'):
                if last_character != '-':
                    result += '_'
                    last_character = '_'
        return str(result).strip('_')

    @staticmethod
    def normalize_email(email: str):
        email = email or ""
        try:
            email_name, domain_part = email.strip().rsplit("@", 1)
        except ValueError:
            pass
        else:
            email = email_name + "@" + domain_part.lower()
        return email


class User(AbstractBaseUser):
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    @property
    def is_staff(self):
        return self.is_admin

    objects = UserManager()
    phone = models.CharField(
        unique=True,
        blank=False,
        null=False,
        max_length=11,
        verbose_name='Phone Number'
    )
    username = models.CharField(unique=True, max_length=255, verbose_name='username', blank=True, null=True)
    email = models.EmailField(max_length=255, blank=True, verbose_name='Email Address', null=True)
    is_email_verify = models.BooleanField(default=False)
    fname = models.CharField(max_length=255, blank=True)
    lname = models.CharField(max_length=255, blank=True)
    image = models.ImageField(upload_to='users_images', null=True, blank=True)
    USERNAME_FIELD = 'phone'
    REQUIRED_FIELDS = []

    def __str__(self):
        return f"{self.phone} {self.username} {self.email}"

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True

class Otp(models.Model):
    code = models.CharField(max_length=4)
    token = models.CharField(max_length=255)
    phone = models.CharField(max_length=11)
    created_at = models.DateTimeField(auto_now_add=True)

    @staticmethod
    def clean_otp():
        Otp.objects.filter(created_at__lte=(timezone.now() - timedelta(minutes=5))).delete()