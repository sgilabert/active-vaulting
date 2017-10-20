import os
import urllib

from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, Http404
from django.shortcuts import render, redirect
from django.conf import settings
from django.utils.datastructures import MultiValueDictKeyError

from core import utilities as core_utilities
import logging

from dropbox.exceptions import ApiError, AuthError, BadInputError

from core import safewalk
from core.utilities import read_secret
from . import utilities
from django.utils.encoding import smart_str

logger = logging.getLogger(__name__)

# Create your views here.

def get_access_token(request):
  # For development, read it from env variables
  access_token = os.environ.get(settings.ENVIRONMENT_OAUTH2_DROPBOX_ACCESS_TOKEN)
  # Read it from the session
  if access_token is None:
    access_token = request.session.get('access_token')
  # If it is not available in the session, use Safewalk active vaulting service
  if access_token is None:
    secrets = read_secrets(request.user)
    access_token = secrets.get('access_token')
    if access_token:
      request.session['access_token'] = access_token
  return access_token

@login_required
def index(request):

    access_token = get_access_token(request)

    sort_field = request.GET.get('sort')
    reverse = request.GET.get('reverse')

    if sort_field is None or reverse is None or sort_field not in ['name', 'last_modified', 'size'] or reverse not in ['t', 'f']:
      return redirect('{}?sort=name&reverse=f'.format(request.path))


    if access_token is None:
      logger.error("Fail to read secrets.")
      return render(request, 'fileshare/error.html', {'message' : 'Error : Fail to read secrets'}, status=500)

    else:
      try :

        file_list = utilities.file_list(access_token, sort_field, reverse)
        return render(request, 'fileshare/index.html', {'file_list' : file_list})
      except (AuthError, BadInputError):
        return render(request, 'fileshare/error.html', {'message' : 'Invalid authentication token'}, status=500)


@login_required
def download(request, filename):

  access_token = get_access_token(request)

  if access_token is None:
    logger.error("Fail to read secrets.")
    return render(request, 'fileshare/error.html', {'message' : 'Fail to read secrets'}, status=500)

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
    except AuthError, e:
      return render(request, 'fileshare/error.html', {'message': 'Invalid authentication token'}, status=500)
    except ApiError:
      raise Http404()

@login_required
def upload(request):

  access_token = get_access_token(request)

  if access_token is None:
    logger.error("Fail to read secrets.")
    return render(request, 'fileshare/error.html', {'message' : 'Fail to read secrets'}, status=500)

  else:
    try:
      r = utilities.upload_file(access_token, request.FILES['upload'].name, request.FILES['upload'])
      return redirect('/?sort={}&reverse={}'.format(request.GET.get('sort', 'name'), request.GET.get('reverse', 'f')))
    except AuthError, e:
      return render(request, 'fileshare/error.html', {'message': 'Invalid authentication token'}, status=500)
    except MultiValueDictKeyError:
      return redirect('/?sort={}&reverse={}'.format(request.GET.get('sort', 'name'), request.GET.get('reverse', 'f')))

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
