from django.core.management.base import BaseCommand, CommandError
from imapclient import utilities

class Command(BaseCommand):
    help = 'Reads the inbox from the given account and show <sender> | <subject>'

    def add_arguments(self, parser):
        parser.add_argument('account', type=str)
        parser.add_argument('password', type=str)


    def handle(self, *args, **options):

        # Parameters
        account = options['account']
        password = options['password']

        mails = utilities.read_mailbox(account, password)

        for mail in mails:
            self.stdout.write('[%s] %s' % (mail['sender'], mail['subject']))
