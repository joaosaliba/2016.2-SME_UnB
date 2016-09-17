from __future__ import unicode_literals

from django.db import models

# Create your models here.


class Report(models.Model):

    class Meta:
        permissions = (
            ("can_generate", "Can Generate Reports"),
        )
