from django.db import models
from django.contrib.auth.models import User
from django.utils.translation import gettext as _
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin


class EmailUserManager(BaseUserManager):
    pass


class UserPermissions(models.Model):
    
    class Meta:
        permissions = (
            ("can_delete", "Can delete Users"),
            ("can_view", "Can view Users"),
        )
