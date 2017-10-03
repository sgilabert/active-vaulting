import os

from django.http import HttpResponse, Http404
from django.shortcuts import render, redirect
from django.conf import settings
import logging

from dropbox.exceptions import ApiError

from . import utilities
from django.utils.encoding import smart_str

logger = logging.getLogger(__name__)

# Create your views here.

# Used in development
access_token  = os.environ.get(settings.ENVIRONMENT_OAUTH2_DROPBOX_ACCESS_TOKEN)

secrets = dict(access_token=access_token)

def index(request):
    global secrets

    access_token = secrets.get('access_token')

    if access_token is None or request.GET.get('refresh'):
      # TODO : Read from vault
      pass

    if access_token is None:
      logger.error("Fail to read secrets.")
      return render(request, 'fileshare/error.html', status=500)

    else:
      file_list = utilities.file_list(access_token)
      return render(request, 'fileshare/index.html', {'file_list' : file_list})

def download(request, filename):
  global secrets

  access_token = secrets.get('access_token')

  if access_token is None or request.GET.get('refresh'):
    # TODO : Read from vault
    pass

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

def upload(request):
  global secrets

  access_token = secrets.get('access_token')

  if access_token is None or request.GET.get('refresh'):
    # TODO : Read from vault
    pass

  if access_token is None:
    logger.error("Fail to read secrets.")
    return render(request, 'fileshare/error.html', status=500)

  else:
    r = utilities.upload_file(access_token, request.FILES['upload'].name, request.FILES['upload'])
    return redirect('/')