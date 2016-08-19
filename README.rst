=====
Login
=====

Login is a simple Django app to handle Auth0 Authentication.

Quick start
-----------

1. Add "login" and "stronghold" to your INSTALLED_APPS setting like this::

    INSTALLED_APPS = [
        ...
        'login',
        'stronghold',
    ]

2. Include the login URLconf in your project urls.py like this::

    url(r'^login/', include('login.urls')),

3. Include Auth0 information in your settings file ::

    LOGIN_URL = '/login/auth/'
    AUTH0_DOMAIN = '<DOMAIN>'
    AUTH0_CLIENT_ID = '<CLIENT_ID>'
    AUTH0_SECRET = '<SECRET>'
    AUTH0_CALLBACK_URL = '<CALLBACK ie. http://localhost:8000/login/callback_handling/>'
    AUTH0_SUCCESS_URL = '<LANDING PAGE ie. /login/landingpage/>'

4. Include AUTHENTICATION_BACKENDS configuration ::

    AUTHENTICATION_BACKENDS = ('login.auth0authenticate.Auth0Authentication', 'django.contrib.auth.backends.ModelBackend')

5. This app depends on django-stronghold which needs the following added to the MIDDLEWARE_CLASSES ::

    MIDDLEWARE_CLASSES = [
        ....
        'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
        ....
        'stronghold.middleware.LoginRequiredMiddleware',
    ]

