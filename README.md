# SciAuth

This Django app is a simple implementation of the Auth0 integration.

The main job is to handle the back and forth relay that happens when a user logs in via Auth0. A JWT, entitled **DBMI_JWT**, will be give to the user so that they can get into other resources that look for that JWT.

## Required Configurations

A number of configurations are required to run the application, mostly related to Auth0. In the Docker these are contained in environment variables, It's easiest to override them in your local settings file. You can find these settings in your auth0 account (you can set up a free developer account).

### Auth0

~~~
AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN")
AUTH0_CLIENT_ID = os.environ.get("AUTH0_CLIENT_ID")
AUTH0_SECRET = os.environ.get("AUTH0_SECRET")
AUTH0_CALLBACK_URL = os.environ.get("AUTH0_CALLBACK_URL")
AUTH0_SUCCESS_URL = os.environ.get("AUTH0_SUCCESS_URL")
AUTH0_LOGOUT_URL = os.environ.get("AUTH0_LOGOUT_URL")
~~~

### Other configs
~~~python
# This forces Django to use the custom backend we wrote for Auth0.
AUTHENTICATION_BACKENDS = ('login.auth0authenticate.Auth0Authentication', 'django.contrib.auth.backends.ModelBackend')

# This restricts the cookies we create to the dbmi subdomain.
COOKIE_DOMAIN = ".dbmi.hms.harvard.edu"

# Django config, move this to an ENV in the future
ALLOWED_HOSTS = ['authentication.aws.dbmi.hms.harvard.edu']

# The e-mail address of the site administrator.
ADMIN = [('SITE-ADMIN', os.environ.get("SITE_ADMIN"))]
~~~