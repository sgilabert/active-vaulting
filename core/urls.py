from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^login/$', views.login),
    url(r'^logout/$', 'django.contrib.auth.views.logout',{'next_page': '/login'}),
    url(r'^sessioncheck/$', views.session_ckeck)
]