from django.db import models

# Create your models here.

class TmpDropboxAccessTokenRetrieval(models.Model):
  session_key = models.CharField(max_length=64, unique=True)
  status = models.CharField(max_length=256, blank=True, null=True)
  access_token = models.CharField(max_length=256, blank=True, null=True)