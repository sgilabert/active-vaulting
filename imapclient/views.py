import os

from django.shortcuts import render
from . import utilities as imapclient_utilities
from core import utilities as core_utilities
from . import safewalk
from django.conf import settings
from time import sleep
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

def read_secret(secret_name):    
    attempts = os.getenv('SECRET_READ_ATTEMPTS', 13)
    fullpath = os.path.join(settings.IMAPCLIENT_MOUNT_LOCATION, secret_name)
    while attempts > 0:
        try :
            with open(fullpath, 'r') as f:
                return f.readline().replace('\n','')
        except IOError as e:
            #logger.exception('Fail to read %s' % secret_name)
            logger.error("Waiting for secrets to be written to propagate on destination account (retrying in 5 seconds)")
            attempts = attempts - 1
            sleep(5)
    return None

# Used in development
account  = os.environ.get(settings.ENVIRONMENT_IMAPCLIENT_ACCOUNT_NAME)
password = os.environ.get(settings.ENVIRONMENT_IMAPCLIENT_ACCOUNT_PASSWORD)

secrets = dict(account=account, password=password)

def index(request):
    global secrets

    account  = secrets.get('account')
    password = secrets.get('password')

    if account is None or password is None or request.GET.get('refresh'):
        secrets = read_secrets()
        account = secrets.get('account')
        password = secrets.get('password')

    if account is None or password is None:
        logger.error("Fail to read secrets.")
        return render(request, 'fileshare/error.html', status=500)

    else:
        return render(request, 'fileshare/index.html', {
            'account': account,
            'mails' : imapclient_utilities.read_mailbox(account, password)
        })
