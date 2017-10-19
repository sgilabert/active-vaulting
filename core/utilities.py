import base64
import hashlib
from time import sleep

from Crypto import Random
from Crypto.Cipher import AES
import os
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

class AESCipher(object):

    def __init__(self, key):
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


def read_secret(secret_name):
  attempts = os.getenv(settings.SECRET_READ_ATTEMPTS, 30)
  fullpath = os.path.join(settings.SECRET_MOUNT_LOCATION, secret_name)
  while attempts > 0:
    try:
      with open(fullpath, 'r') as f:
        return f.readline().replace('\n', '')
    except IOError as e:
      # logger.exception('Fail to read %s' % secret_name)
      logger.error("Waiting for secrets to be written to propagate on destination account (retrying in 5 seconds)")
      attempts = attempts - 1
      sleep(5)
  return None