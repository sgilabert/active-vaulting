import requests
from wsgiref.util import is_hop_by_hop
import logging

logger = logging.getLogger(__name__)

class SafewalkClient(object):

  def __init__(self, service_url, access_token):
      self.service_url  = service_url
      self.access_token = access_token

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