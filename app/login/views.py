from django.shortcuts import render, redirect, reverse
from django.conf import settings
from django.http import HttpResponse, QueryDict
from django.contrib.auth.models import User
from django.contrib.auth import login, logout
from django.contrib import auth as django_auth
from pyauth0jwt.auth0authenticate import user_auth_and_jwt
from .sciauthz_services import get_sciauthz_project
from SciAuth import scireg_services
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from urllib import parse
import requests
import json
import logging
import base64
import furl
import pickle
import jwt

logger = logging.getLogger(__name__)


def auth(request):
    """
    Landing point to force user log in.

    This URL is a catch-all to see if a user is already logged in. The next Querystring should be set to
    redirect if the user is found to be logged in, or after they log in.
    """
    logger.debug("Checking if user is logged in already.")

    if request.user.is_authenticated() and request.COOKIES.get("DBMI_JWT", None) is not None:
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

    # This is a code passed back from Auth0 that is used to retrieve a token (Which is used to retrieve user info).
    code = request.GET.get('code')
    if not code:
        logger.error('Auth0 returned no code: {}'.format(request.GET))

        # Check for error descriptors
        if request.GET.get('error'):
            logger.error('Auth0 error: {}'.format(request.GET.get('error')))
        if request.GET.get('error_description'):
            logger.error('Auth0 error description: {}'.format(request.GET.get('error_description')))

        # Get the original query sent to SciAuth
        query = QueryDict(base64.urlsafe_b64decode(request.GET.get('query').encode('utf-8')).decode('utf-8'))
        url = reverse('auth') + '?{}'.format(query.urlencode('/'))
        logger.debug('Redirect back to SciAuth: {}'.format(url))

        # Redirect back to the auth screen and attach the original query
        return redirect(url)

    json_header = {'content-type': 'application/json'}

    # This is the Auth0 URL we post the code to in order to get token.
    token_url = 'https://%s/oauth/token' % settings.AUTH0_DOMAIN

    # Information we pass to auth0, helps identify us and our request.
    token_payload = {
        'client_id': settings.AUTH0_CLIENT_ID,
        'client_secret': base64.b64decode(settings.AUTH0_SECRET, '-_').decode('utf-8'),
        'redirect_uri': settings.AUTH0_CALLBACK_URL,
        'code': code,
        'grant_type': 'authorization_code'
    }

    # Post the code to get the token from Auth0.
    token_info = requests.post(token_url,data=json.dumps(token_payload),headers=json_header).json()

    # URL we post the token to get user info.
    url = 'https://%s/userinfo?access_token=%s'
    user_url = url % (settings.AUTH0_DOMAIN,token_info.get('access_token', ''))

    # Get the user info from auth0.
    user_info = requests.get(user_url).json()

    # Check for an existing user
    new_user = User.objects.filter(username=user_info['email']).count() == 0
    logger.debug('New user? {}'.format(new_user))

    # We're saving all user information into the session
    request.session['profile'] = user_info
    user = django_auth.authenticate(**user_info)

    # If everything is good and we have the user info we can proceed.
    if user:
        logger.debug("User is good, proceeding")

        # Log the user into the SciAuth Django App.
        login(request, user)

        # Get the JWT token
        jwt = token_info['id_token']

        try:
            # Get the original query string
            query = QueryDict(base64.urlsafe_b64decode(request.GET.get('query').encode('utf-8')).decode('utf-8'))
            logger.debug('Original query: {}'.format(query))
        except Exception as e:
            # Use an empty query dict
            query = QueryDict()
            logger.exception(e)

        # Get the project, if any.
        project = query.get('project', 'hms')

        try:
            # Check for a new user.
            email_confirm_success_url = query.get('email_confirm_success_url')
            if email_confirm_success_url and new_user:

                # Start email verification
                response = scireg_services.send_confirmation_email(jwt, email_confirm_success_url, project)
                logger.debug('Email confirmation response: {}: {}'
                             .format(response.status_code, response.content))

        except Exception as e:
            logger.exception(e)

        # Redirect the user to the page they originally requested.
        redirect_url = query.get('next', settings.AUTH0_SUCCESS_URL)
        logger.debug('Redirecting user to: {}'.format(redirect_url))

        response = redirect(redirect_url)

        # Set the JWT into a cookie in the response.
        response.set_cookie('DBMI_JWT', jwt, domain=settings.COOKIE_DOMAIN, httponly=True)

        logger.debug("User logged in, returning.")

        return response

    else:
        logger.error("User is NOT good")

    return HttpResponse(status=400)

@csrf_exempt
def validate_jwt(request):
    logger.debug("Validating JWT")

    jwt_to_validate = request.POST.get('jwt', '')

    # Check that we actually have a token.
    if jwt_to_validate is not None:

        # Attempt to validate the JWT (Checks both expiry and signature)
        try:
            jwt.decode(jwt_to_validate,
                                 base64.b64decode(settings.AUTH0_SECRET, '-_'),
                                 algorithms=['HS256'],
                                 leeway=120,
                                 audience=settings.AUTH0_CLIENT_ID)

            response_data = {"status": "VALID"}

        except jwt.InvalidTokenError:
            logger.error("JWT token is invalid")
            response_data = {"stauts": "INVALID"}
        except jwt.ExpiredSignatureError:
            logger.error("JWT token expired")
            response_data = {"status": "EXPIRED_SIGNATURE"}
    else:
        logger.error("JWT token is missing")
        response_data = {"status": "NO_JWT"}

    return JsonResponse(response_data)


@user_auth_and_jwt
def logout_view(request):
    """
    User logout

    This endpoint logs out the user session from the SciAuth Django app.
    """
    logger.debug("User is logging out, redirecting to: {}".format(settings.AUTH0_LOGOUT_URL))
    logout(request)
    return redirect(settings.AUTH0_LOGOUT_URL)

@user_auth_and_jwt
def landingpage(request):
    logger.debug("Landing page")
    return render(request, 'login/landingpage.html')
