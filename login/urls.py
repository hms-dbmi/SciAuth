from django.conf.urls import url

urlpatterns = [
    url(r'^auth/$', 'auth', {'template_name': 'login/auth.html'}, name='auth')
]


