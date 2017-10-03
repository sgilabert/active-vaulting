from django.conf.urls import include, url
from fileshare.views import index
from . import views

urlpatterns = [
    url(r'^download/(?P<filename>[^/]+)/$', views.download),
    url(r'^upload/$', views.upload),
]
