from django.conf import settings
import os

from django.contrib.auth import get_user_model
from django.shortcuts import render
from requests import ConnectionError

from core.backends import RemoteUserBackend
from core.safewalk import SafewalkClient, AuthenticationException
from django.http import HttpResponseRedirect, HttpResponseNotAllowed, JsonResponse, Http404, HttpResponseServerError
from django.contrib import auth

from core.utilities import read_secret


def login(request):

  def read_session_key(service_url, access_token):
    r = SafewalkClient(service_url=service_url, access_token=access_token).get_session_key()
    return r['session-key'] if r else None

  safewalk_url, authentication_access_token = _get_safewalk_configuration()

  if not safewalk_url or not authentication_access_token:
    return render(request, 'core/login.html', {'message' : 'Safewalk authentication service is not properly configured.'})

  if request.method == 'POST':

    username = request.POST.get("username", "")
    password = request.POST.get("password", "")
    try :
      client = SafewalkClient.authenticate(safewalk_url, authentication_access_token, username, password)
      user = auth.authenticate(remote_user=client.username, access_token=client.access_token)
      auth.login(request, user)
      if user:
        redirect_to = request.GET.get('next', '/')
        return HttpResponseRedirect(redirect_to)
    except AuthenticationException, e:

      try :
        session_key = read_session_key(safewalk_url, authentication_access_token)
        return render(request, 'core/login.html',{'message': str(e), 'username': e.username, 'session_key': session_key})
      except ConnectionError:
        return render(request, 'core/login.html',{'message': 'Failed to stablish connection with Safewalk authentication service.'})

    except ConnectionError, e:
      return render(request, 'core/login.html', {'message' : 'Failed to stablish connection with Safewalk authentication service.'})

  elif request.method == 'GET':

    redirect_to = request.REQUEST.get('next', '')
    if not redirect_to:
      return HttpResponseRedirect('/')

    try :
        session_key = read_session_key(safewalk_url, authentication_access_token)
        return render(request, 'core/login.html',{'session_key': session_key})
    except ConnectionError:
      return render(request, 'core/login.html', {'message': 'Failed to stablish connection with Safewalk authentication service.'})

  else:
    return HttpResponseNotAllowed(['GET', 'POST'])

def session_ckeck(request):

  return JsonResponse({'is_expired': not request.user.is_authenticated()})

def session_key_verification(request, session_key):

  def get_user(username):
    UserModel = get_user_model()
    user, _ = UserModel.objects.get_or_create(username=username)
    return user

  def update_transaction_log(self, transaction_id, reason):
    self.client.update_transaction_log(transaction_id, reason)

  safewalk_url, authentication_access_token = _get_safewalk_configuration()

  try:
    client = SafewalkClient(safewalk_url, authentication_access_token)
    r = client.check_session_key(session_key)
    if r.status_code == 200:
      if r.json()['code'] == 'ACCESS_ALLOWED':
        user = get_user(r.json()['username'])
        backend = RemoteUserBackend()
        user.backend = "%s.%s" % (backend.__module__, backend.__class__.__name__)
        auth.login(request, user)
      return JsonResponse(r.json())
    return Http404()
  except ConnectionError, e:
    return HttpResponseServerError(str(e))

def _get_safewalk_configuration():

  safewalk_url = os.environ.get(settings.ENVIRONMENT_SAFEWALK_URL)
  authentication_access_token = os.environ.get(settings.ENVIRONMENT_SAFEWALK_ACCESS_TOKEN)

  safewalk_url = safewalk_url or read_secret(settings.SAFEWALK_URL)
  authentication_access_token = authentication_access_token or read_secret(settings.SAFEWALK_ACCESS_TOKEN)

  return safewalk_url, authentication_access_token