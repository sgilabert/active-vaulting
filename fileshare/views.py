import os
import threading

from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, Http404, JsonResponse
from django.shortcuts import render, redirect
from django.conf import settings
from django.utils.datastructures import MultiValueDictKeyError

from core import utilities as core_utilities
import logging

from dropbox.exceptions import ApiError, AuthError, BadInputError

from core import safewalk
from core.utilities import read_secret
from fileshare.models import TmpDropboxAccessTokenRetrieval
from . import utilities
from django.utils.encoding import smart_str
from time import sleep

logger = logging.getLogger(__name__)

# Create your views here.

STATUS_00_START = '00_START'
STATUS_01_APP_QUERY_SECRETS = '01_APP_QUERY_SECRETS'
STATUS_02_SW_GENERATES_RANDOM_KEY = '02_SW_GENERATES_RANDOM_KEY'
STATUS_03_SW_GENERATES_RANDOM_IDENTIFIER = '03_SW_GENERATES_RANDOM_IDENTIFIER'
STATUS_04_SW_WRITES_TO_CLOUD_PROVIDER = '04_SW_WRITES_TO_CLOUD_PROVIDER'
STATUS_05_SW_REPLIES_TO_APP = '05_SW_REPLIES_TO_APP'
STATUS_06_APP_QUERY_THE_CLOUD_PROVIDER = '06_APP_QUERY_THE_CLOUD_PROVIDER'
STATUS_07_APP_DECRYPT_ENCRYPTED_SECRETS = '07_APP_DECRYPT_ENCRYPTED_SECRETS'
STATUS_08_APP_USES_DECRYPTED_SECRETS = '08_APP_USES_DECRYPTED_SECRETS'
STATUS_09_READY = '09_READY'

ERR_99_FAIL_TO_WRITE_ENCRYPTED_SECRETS = 'ERR_99_FAIL_TO_WRITE_ENCRYPTED_SECRETS'
ERR_99_VAULT_DEVICE_NOT_FOUND = 'ERR_99_VAULT_DEVICE_NOT_FOUND'
ERR_99_FAIL_TO_QUERY_CLOUD_PROVIDER = 'ERR_99_FAIL_TO_QUERY_CLOUD_PROVIDER'
ERR_99_UNEXPECTED = 'ERR_99_UNEXPECTED'

MESSAGES = {
  ERR_99_FAIL_TO_WRITE_ENCRYPTED_SECRETS : 'Safewalk failed to write encrypted secrets',
  ERR_99_VAULT_DEVICE_NOT_FOUND : 'User doesn\'t have permissions to access Dropbox service',
  ERR_99_FAIL_TO_QUERY_CLOUD_PROVIDER : 'Fail to read the secrets from the cloud provider',
  ERR_99_UNEXPECTED : 'Fail to read secrets'
}

@login_required
def index(request):

    sort_field = request.GET.get('sort')
    reverse = request.GET.get('reverse')

    if sort_field is None or reverse is None or sort_field not in ['name', 'last_modified', 'size'] or reverse not in ['t', 'f']:
      return redirect('{}?sort=name&reverse=f'.format(request.path))

    tmp_dropbox_access_token_retrieval = _get_tmp_dropbox_access_token_retrieval(request)

    if not tmp_dropbox_access_token_retrieval.status:
      _set_tmp_dropbox_access_token_retrieval(request, STATUS_00_START, seconds=0)
      t = threading.Thread(target=_get_access_token, args=(request,))
      t.setDaemon(True)
      t.start()
      return render(request, 'fileshare/index.html', {'file_list': None,})
    elif tmp_dropbox_access_token_retrieval.status.startswith('ERR_'):
      return render(request, 'fileshare/error.html', {'message': MESSAGES.get(tmp_dropbox_access_token_retrieval.status)}, status=500)
    elif tmp_dropbox_access_token_retrieval.status == STATUS_09_READY:
        access_token = tmp_dropbox_access_token_retrieval.access_token
        if access_token is None:
          logger.error("Fail to read secrets.")
          return render(request, 'fileshare/error.html', {'message': 'Fail to read secrets'}, status=500)
        else:
          try :
            file_list = utilities.file_list(access_token, sort_field, reverse)
            return render(request, 'fileshare/index.html', {'file_list' : file_list,})
          except (AuthError, BadInputError):
            return render(request, 'fileshare/error.html', {'message' : 'Invalid authentication token'}, status=500)
    else:
      return render(request, 'fileshare/index.html', {'file_list' : None,})


@login_required
def download(request, filename):

  access_token = _get_access_token(request)

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

  access_token = _get_access_token(request)

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

@login_required
def status(request):
  return JsonResponse({'status': _get_tmp_dropbox_access_token_retrieval(request).status})

def _read_secrets(request):

    # Request the secrets to Safewalk
    # -------------------------------
    service_url = os.environ.get(settings.ENVIRONMENT_SAFEWALK_URL)
    if not service_url:
      service_url = read_secret(settings.SAFEWALK_URL)

    decrypted_access_token = None

    if service_url:

      client = safewalk.SafewalkClient(service_url, request.user.access_token)
      _set_tmp_dropbox_access_token_retrieval(request, STATUS_01_APP_QUERY_SECRETS)
      secrets = client.get_secrets()

      if secrets and secrets['result'] == 'SUCCESS':

        _set_tmp_dropbox_access_token_retrieval(request, STATUS_02_SW_GENERATES_RANDOM_KEY)
        _set_tmp_dropbox_access_token_retrieval(request, STATUS_03_SW_GENERATES_RANDOM_IDENTIFIER)
        _set_tmp_dropbox_access_token_retrieval(request, STATUS_04_SW_WRITES_TO_CLOUD_PROVIDER)
        _set_tmp_dropbox_access_token_retrieval(request, STATUS_05_SW_REPLIES_TO_APP)

        key = secrets['key']
        identifier = secrets['identifier']

        # Read the secrets
        # ----------------

        _set_tmp_dropbox_access_token_retrieval(request, STATUS_06_APP_QUERY_THE_CLOUD_PROVIDER)
        encrypted_access_token = read_secret('%s.%s' % (identifier, settings.OAUTH2_DROPBOX_ACCESS_TOKEN))

        # Decrypt the secrets
        # -------------------
        cipher = core_utilities.AESCipher(key)
        if encrypted_access_token:
          _set_tmp_dropbox_access_token_retrieval(request, STATUS_07_APP_DECRYPT_ENCRYPTED_SECRETS)
          decrypted_access_token = cipher.decrypt(encrypted_access_token)
          _set_tmp_dropbox_access_token_retrieval(request, STATUS_08_APP_USES_DECRYPTED_SECRETS)
        else:
          _set_tmp_dropbox_access_token_retrieval(request, ERR_99_FAIL_TO_QUERY_CLOUD_PROVIDER)

      elif secrets and secrets['result'] == 'FAIL_TO_WRITE_ENCRYPTED_SECRETS':
        _set_tmp_dropbox_access_token_retrieval(request, STATUS_02_SW_GENERATES_RANDOM_KEY)
        _set_tmp_dropbox_access_token_retrieval(request, STATUS_03_SW_GENERATES_RANDOM_IDENTIFIER)
        _set_tmp_dropbox_access_token_retrieval(request, ERR_99_FAIL_TO_WRITE_ENCRYPTED_SECRETS)

      elif secrets and secrets['result'] == 'VAULT_DEVICE_NOT_FOUND':
        _set_tmp_dropbox_access_token_retrieval(request, ERR_99_VAULT_DEVICE_NOT_FOUND)

      else:
        _set_tmp_dropbox_access_token_retrieval(request, ERR_99_VAULT_DEVICE_NOT_FOUND)


    return dict(
      access_token=decrypted_access_token
    )

def _get_access_token(request):
  try:
    retrieval = _get_tmp_dropbox_access_token_retrieval(request)
    if retrieval.status == STATUS_09_READY:
      access_token = retrieval.access_token
    else:
      # For development, read it from env variables
      access_token = os.environ.get(settings.ENVIRONMENT_OAUTH2_DROPBOX_ACCESS_TOKEN)
      if access_token:
        _set_tmp_dropbox_access_token_retrieval(request, STATUS_09_READY, access_token)
      else:
        # If it is not available in the session, use Safewalk active vaulting service
        if access_token is None:
          secrets = _read_secrets(request)
          access_token = secrets.get('access_token')
          if access_token:
            _set_tmp_dropbox_access_token_retrieval(request, STATUS_09_READY, access_token)

      return access_token
  except:
    _set_tmp_dropbox_access_token_retrieval(request, ERR_99_UNEXPECTED, None)


status_threads = {}
def _set_tmp_dropbox_access_token_retrieval(request, status, acces_token=None, seconds=None):
  global status_threads

  def update_status(request, status, acces_token=None, seconds=None):
    tmp_access_token_retrieval = TmpDropboxAccessTokenRetrieval.objects.get_or_create(session_key = request.session.session_key)[0]
    tmp_access_token_retrieval.status = status
    tmp_access_token_retrieval.access_token = acces_token
    tmp_access_token_retrieval.save()
    seconds = seconds or os.environ.get(settings.ENVIRONMENT_IMAGE_DEMO_DELAY, 5)
    sleep(seconds)

  progress_thread = status_threads.get(request.session.session_key)
  if progress_thread is not None:
    progress_thread.join()
  status_threads[request.session.session_key] = threading.Thread(target=update_status, args=(request, status, acces_token, seconds))
  status_threads[request.session.session_key].setDaemon(True)
  status_threads[request.session.session_key].start()


def _get_tmp_dropbox_access_token_retrieval(request):
  retrieval = TmpDropboxAccessTokenRetrieval.objects.get_or_create(session_key = request.session.session_key)[0]
  return retrieval