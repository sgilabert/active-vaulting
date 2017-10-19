from django.conf import settings
import os

from django.shortcuts import render
from requests import ConnectionError

from core.safewalk import SafewalkClient, AuthenticationException
from django.http import HttpResponseRedirect, HttpResponseNotAllowed, JsonResponse
from django.contrib import auth

from core.utilities import read_secret


def login(request):

  safewalk_url = os.environ.get(settings.ENVIRONMENT_SAFEWALK_URL)
  authentication_access_token = os.environ.get(settings.ENVIRONMENT_SAFEWALK_ACCESS_TOKEN)

  safewalk_url = safewalk_url or read_secret(settings.SAFEWALK_URL)
  authentication_access_token = authentication_access_token or read_secret(settings.SAFEWALK_ACCESS_TOKEN)

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
      return render(request, 'core/login.html', {'message' : str(e), 'username' : e.username})
    except ConnectionError, e:
      return render(request, 'core/login.html', {'message' : 'Failed to stablish connection with Safewalk authentication service.'})

  elif request.method == 'GET':
    return render(request, 'core/login.html')

  else:
    return HttpResponseNotAllowed(['GET', 'POST'])

def session_ckeck(request):

  return JsonResponse({'is_expired': not request.user.is_authenticated()})





