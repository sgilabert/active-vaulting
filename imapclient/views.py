import os

from django.shortcuts import render

from core.utilities import read_secret
from . import utilities as imapclient_utilities
from core import utilities as core_utilities
from core import safewalk
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

def read_secrets():

    # Request the secrets to Safewalk
    # -------------------------------
    service_url  = read_secret(settings.SAFEWALK_URL)
    access_token = read_secret(settings.SAFEWALK_ACCESS_TOKEN)

    decrypted_account = None
    decrypted_password = None

    if service_url and access_token:

        client = safewalk.SafewalkClient(service_url, access_token)
        secrets = client.get_secrets()

        if secrets :

            if secrets is not None and secrets['result'] == 'SUCCESS':

                key        = secrets['key']
                identifier = secrets['identifier']

                # Read the secrets
                # ----------------

                encrypted_account  = read_secret('%s.%s' % (identifier, settings.IMAPCLIENT_ACCOUNT_NAME))
                encrypted_password = read_secret('%s.%s' % (identifier, settings.IMAPCLIENT_ACCOUNT_PASSWORD))

                # Decrypt the secrets
                # -------------------
                cipher = core_utilities.AESCipher(key)
                if encrypted_account:
                  decrypted_account  = cipher.decrypt(encrypted_account)
                if encrypted_password:
                  decrypted_password = cipher.decrypt(encrypted_password)

    return dict(
        account=decrypted_account,
        password=decrypted_password
    )


# Used in development
account  = os.environ.get(settings.ENVIRONMENT_IMAPCLIENT_ACCOUNT_NAME)
password = os.environ.get(settings.ENVIRONMENT_IMAPCLIENT_ACCOUNT_PASSWORD)

secrets = dict(account=account, password=password)

def index(request):
    global secrets

    account  = secrets.get('account')
    password = secrets.get('password')

    if request.GET.get('refresh'):
      account = os.environ.get(settings.ENVIRONMENT_IMAPCLIENT_ACCOUNT_NAME)
      password = os.environ.get(settings.ENVIRONMENT_IMAPCLIENT_ACCOUNT_PASSWORD)
      secrets = dict(account=account, password=password)

    if account is None or password is None:
        secrets = read_secrets()
        account = secrets.get('account')
        password = secrets.get('password')

    if account is None or password is None:
        logger.error("Fail to read secrets.")
        return render(request, 'imapclient/error.html', status=500)

    else:
        return render(request, 'imapclient/index.html', {
            'account': account,
            'mails' : imapclient_utilities.read_mailbox(account, password)
        })
