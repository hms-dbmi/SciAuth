from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^auth/$', views.auth,  name='auth'),
    url(r'^landingpage/$', views.landingpage,  name='landingpage'),
    url(r'^callback_handling/$', views.callback_handling,  name='callback_handling'),
]


