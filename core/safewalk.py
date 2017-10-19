import requests
from wsgiref.util import is_hop_by_hop
from django.conf import settings
import logging
import os

logger = logging.getLogger(__name__)

safewalk_url  = os.environ.get(settings.ENVIRONMENT_SAFEWALK_URL)
authentication_access_token = os.environ.get(settings.ENVIRONMENT_SAFEWALK_ACCESS_TOKEN)

class AuthenticationException(Exception):

  def __init__(self, msg, username):
    super(AuthenticationException, self).__init__(msg)
    self.username = username

class SafewalkClient(object):

  @classmethod
  def authenticate(cls, service_url, authentication_access_token, username, password):
    payload = {'username': username, 'password': password}
    url = service_url + '/api/v1/auth/authenticate/'
    headers = {'AUTHORIZATION': 'Bearer {}'.format(authentication_access_token)}
    r = requests.post(url, payload, verify=settings.VERIFY_SSL, headers=headers)
    for header in r.headers.keys():
      if is_hop_by_hop(header):
        # logger.debug('hop_by_hop headers not supported. Deleting %s' %(header))
        del r.headers[header]
    if r.status_code == 200:
      return SafewalkClient(service_url, r.json()['access-token'], username=r.json()['username'])
    else:
      message = r.json().get('reply-message', r.content)
      username = r.json().get('username')
      raise AuthenticationException(message, username)

  def __init__(self, service_url, access_token, *args, **kwargs):
    self.service_url  = service_url
    self.access_token = access_token
    self.username = kwargs.get('username', 'UNDEFINED')

  def _do_request(self, method, *args, **kwargs):
    r = method(verify=False, *args, **kwargs)
    for header in r.headers.keys():
      if is_hop_by_hop(header):
        del r.headers[header]
    logger.debug('Safewalk response %s' % r.content)
    return r

  def _post(self, function, payload=None):
    url = self.service_url + function
    headers = {'AUTHORIZATION': 'Bearer {}'.format(self.access_token)}
    args = (url,)
    kwargs = {'data':payload, 'headers':headers}
    method = requests.post
    return self._do_request(method, *args, **kwargs)

  def get_secrets(self):
    r = self._post('/api/v1/auth/vault/')
    if r.status_code == 200:
      return r.json()
    return None