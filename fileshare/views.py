import os

from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, Http404
from django.shortcuts import render, redirect
from django.conf import settings
from core import utilities as core_utilities
import logging

from dropbox.exceptions import ApiError

from core import safewalk
from core.utilities import read_secret
from . import utilities
from django.utils.encoding import smart_str

logger = logging.getLogger(__name__)

# Create your views here.

# Used in development
access_token  = os.environ.get(settings.ENVIRONMENT_OAUTH2_DROPBOX_ACCESS_TOKEN)

secrets = dict(access_token=access_token)

@login_required
def index(request):
    global secrets

    access_token = secrets.get('access_token')

    if request.GET.get('refresh'):
      access_token = os.environ.get(settings.ENVIRONMENT_OAUTH2_DROPBOX_ACCESS_TOKEN)
      secrets = dict(access_token=access_token)

    if access_token is None:
      secrets = read_secrets(request.user)
      access_token = secrets.get('access_token')

    if access_token is None:
      logger.error("Fail to read secrets.")
      return render(request, 'fileshare/error.html', status=500)

    else:
      file_list = utilities.file_list(access_token)
      return render(request, 'fileshare/index.html', {'file_list' : file_list})

@login_required
def download(request, filename):
  global secrets

  access_token = secrets.get('access_token')

  if request.GET.get('refresh'):
    access_token = os.environ.get(settings.ENVIRONMENT_OAUTH2_DROPBOX_ACCESS_TOKEN)
    secrets = dict(access_token=access_token)

  if access_token is None:
    secrets = read_secrets(request.user)
    access_token = secrets.get('access_token')

  if access_token is None:
    logger.error("Fail to read secrets.")
    return render(request, 'fileshare/error.html', status=500)

  else:
    try :
      r = utilities.download_file(access_token, '/%s' % filename)[1]
      response = HttpResponse(
        content=r.content,
        status=r.status_code,
        content_type=r.headers['Content-Type']
      )
      response['Content-Disposition'] = 'attachment; filename=%s' % smart_str(filename)
      return response
    except ApiError:
      raise Http404()

@login_required
def upload(request):
  global secrets

  access_token = secrets.get('access_token')

  if request.GET.get('refresh'):
    access_token = os.environ.get(settings.ENVIRONMENT_OAUTH2_DROPBOX_ACCESS_TOKEN)
    secrets = dict(access_token=access_token)

  if access_token is None:
    secrets = read_secrets(request.user)
    access_token = secrets.get('access_token')

  if access_token is None:
    logger.error("Fail to read secrets.")
    return render(request, 'fileshare/error.html', status=500)

  else:
    r = utilities.upload_file(access_token, request.FILES['upload'].name, request.FILES['upload'])
    return redirect('/')

def read_secrets(user):

    # Request the secrets to Safewalk
    # -------------------------------
    service_url = os.environ.get(settings.ENVIRONMENT_SAFEWALK_URL)
    if not service_url:
      service_url = read_secret(settings.SAFEWALK_URL)

    decrypted_access_token = None

    if service_url:

      client = safewalk.SafewalkClient(service_url, user.access_token)
      secrets = client.get_secrets()

      if secrets:

        if secrets is not None and secrets['result'] == 'SUCCESS':

          key = secrets['key']
          identifier = secrets['identifier']

          # Read the secrets
          # ----------------

          encrypted_access_token = read_secret('%s.%s' % (identifier, settings.OAUTH2_DROPBOX_ACCESS_TOKEN))

          # Decrypt the secrets
          # -------------------
          cipher = core_utilities.AESCipher(key)
          if encrypted_access_token:
            decrypted_access_token = cipher.decrypt(encrypted_access_token)

    return dict(
      access_token=decrypted_access_token
    )
