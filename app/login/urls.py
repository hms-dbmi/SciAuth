from django.conf.urls import url
from . import views

from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    url(r'^$', views.landingpage, name="landingpage"),
    url(r'^auth$', views.auth,  name='auth'),
    url(r'^landingpage/$', views.landingpage,  name='landingpage'),
    url(r'^callback_handling/$', views.callback_handling,  name='callback_handling'),
    url(r'^logout/$', views.logout_view,  name='logout'),
    url(r'^validate_jwt', views.validate_jwt,  name='validate_jwt'),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)


