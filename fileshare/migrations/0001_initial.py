# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='TmpDropboxAccessTokenRetrieval',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('session_key', models.CharField(unique=True, max_length=64)),
                ('status', models.CharField(max_length=256, null=True, blank=True)),
                ('access_token', models.CharField(max_length=256, null=True, blank=True)),
            ],
        ),
    ]
