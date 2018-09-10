import requests
import json
import base64
import furl

from django.shortcuts import render, redirect, reverse
from django.conf import settings
from django.http import HttpResponse, QueryDict
from pyauth0jwt.auth0authenticate import dbmi_jwt, validate_request

import logging
logger = logging.getLogger(__name__)


def auth(request):
    """
    Landing point to force user log in.

    This URL is a catch-all to see if a user is already logged in. The next Querystring should be set to
    redirect if the user is found to be logged in, or after they log in.
    """
    logger.debug("Checking if user is logged in already.")

    # Check for an existing valid DBMI JWT
    if validate_request(request):
        logger.debug("Logged in, forward along.")

        redirect_url = request.GET.get("next", settings.AUTH0_SUCCESS_URL)
        return redirect(redirect_url)

    # Initialize the context.
    context = {
        'auth0_callback_url': settings.AUTH0_CALLBACK_URL,
        'auth0_client_id': settings.AUTH0_CLIENT_ID,
        'auth0_domain': settings.AUTH0_DOMAIN,
    }

    # Build the redirect URL
    return_url = furl.furl(settings.AUTH0_CALLBACK_URL)

    # Pass along any parameters as base64 encoded
    query = base64.urlsafe_b64encode(request.META.get('QUERY_STRING').encode('utf-8')).decode('utf-8')
    return_url.query.params.add('query', query)

    logger.debug('Return URL: {}'.format(return_url.url))

    # Add to the context.
    context['return_url'] = return_url.url

    # Check for a branding dict
    project_branding = request.GET.get('branding', None)
    if project_branding:

        try:
            # Decode it
            branding_json = base64.urlsafe_b64decode(project_branding.encode('utf-8')).decode('utf-8')
            project = json.loads(branding_json)

            logger.debug("Project branding: {}".format(project))

            # Add the title and description to the context.
            context['project'] = project.get('id', None)
            context['project_title'] = project.get('title', None)
            context['project_icon_url'] = project.get('icon_url', None)

        except Exception as e:
            logger.exception(e)
            logger.error("Project branding parsing failed")

    else:
        logger.debug("No project identifier/branding passed")

    return render(request, 'login/auth.html', context)


def callback_handling(request):
    """
    Callback from Auth0

    This endpoint is called by auth0 with a code that lets us know the user logged into their Identity Provider successfully.
    We need to use the code to gather the user information from Auth0 and establish the DBMI_JWT cookie.
    """
    logger.debug("Call returned from Auth0.")

    # Fetch some of the request parameters
    query = None
    auth_url = None
    try:
        # Get the original query sent to dbmiauth
        query = QueryDict(base64.urlsafe_b64decode(request.GET.get('query').encode('utf-8')).decode('utf-8'))

        # Get the return URL
        auth_url = reverse('auth') + '?{}'.format(query.urlencode('/'))

    except Exception as e:
        logger.error('Failed to parse query parameters: {}'.format(e), exc_info=True, extra={'request': request})

    # This is a code passed back from Auth0 that is used to retrieve a token (Which is used to retrieve user info).
    code = request.GET.get('code')
    if not code:
        logger.error('No code from Auth0', exc_info=True, extra={'request': request})

        # Redirect back to the auth screen and attach the original query
        return redirect(auth_url)

    json_header = {'content-type': 'application/json'}

    # This is the Auth0 URL we post the code to in order to get token.
    token_url = 'https://%s/oauth/token' % settings.AUTH0_DOMAIN

    # Information we pass to auth0, helps identify us and our request.
    token_payload = {
        'client_id': settings.AUTH0_CLIENT_ID,
        'client_secret': base64.b64decode(settings.AUTH0_SECRET.encode()).decode(),
        'redirect_uri': settings.AUTH0_CALLBACK_URL,
        'code': code,
        'grant_type': 'authorization_code'
    }

    # Post the code to get the token from Auth0.
    token_response = requests.post(token_url, data=json.dumps(token_payload), headers=json_header)
    if not token_response.ok:
        logger.error('Failed to exchange token', exc_info=True, extra={
            'request': request, 'response': token_response.content,
            'status': token_response.status_code, 'url': token_url,
        })

        # Redirect back to the auth screen and attach the original query
        return redirect(auth_url)

    # Get tokens
    token_info = token_response.json()

    # URL we post the token to get user info.
    url = 'https://%s/userinfo?access_token=%s'
    user_url = url % (settings.AUTH0_DOMAIN,token_info.get('access_token', ''))

    # Get the user info from auth0.
    user_response = requests.get(user_url)
    if not user_response.ok:
        logger.error('Failed to get user info', exc_info=True, extra={
            'request': request, 'response': user_response.content,
            'status': user_response.status_code, 'url': user_url,
        })

        # Redirect back to the auth screen and attach the original query
        return redirect(auth_url)

    # Get user info
    user_info = user_response.json()
    email = user_info.get('email')
    jwt = token_info.get('id_token')
    if email and jwt:

        # Redirect the user to the page they originally requested.
        redirect_url = query.get('next', settings.AUTH0_SUCCESS_URL)
        logger.debug('Redirecting user to: {}'.format(redirect_url))

        response = redirect(redirect_url)

        # Set the JWT into a cookie in the response.
        response.set_cookie('DBMI_JWT', jwt, domain=settings.COOKIE_DOMAIN, httponly=True)
        logger.debug("User logged in, returning.")

        return response

    else:
        logger.error("No email/jwt returned for user info, cannot proceed", exc_info=True, extra={'user_info': user_info})

    return HttpResponse(status=400)


@dbmi_jwt
def logout_view(request):
    """
    User logout

    This endpoint logs out the user session from the dbmiauth Django app.
    """
    logger.debug("User is logging out, redirecting to: {}".format(settings.AUTH0_LOGOUT_URL))
    return redirect(settings.AUTH0_LOGOUT_URL)


@dbmi_jwt
def landingpage(request):
    logger.debug("Landing page")
    return render(request, 'login/landingpage.html')
