from django.shortcuts import render, redirect
from django.conf import settings
from django.http import HttpResponse
from django.contrib.auth import login, logout
from django.contrib import auth as django_auth
from pyauth0jwt.auth0authenticate import user_auth_and_jwt
from .sciauthz_services import get_sciauthz_project

from urllib import parse
import requests
import json
import logging
import base64

logger = logging.getLogger(__name__)


def auth(request):
    """
    Landing point to force user log in.

    This URL is a catch-all to see if a user is already logged in. The next Querystring should be set to
    redirect if the user is found to be logged in, or after they log in.
    """

    logger.debug("[SCIAUTH][DEBUG][auth] - Checking if user is logged in already.")

    if request.user.is_authenticated() and request.COOKIES.get("DBMI_JWT", None) is not None:
        logger.debug("[SCIAUTH][DEBUG][auth] - Logged in, forward along.")

        redirect_url = request.GET.get("next", settings.AUTH0_SUCCESS_URL)
        return redirect(redirect_url)

    # Initialize the context.
    context = {
        'auth0_callback_url': settings.AUTH0_CALLBACK_URL,
        'auth0_client_id': settings.AUTH0_CLIENT_ID,
        'auth0_domain': settings.AUTH0_DOMAIN,
    }

    # Check for a project id.
    project_id = request.GET.get('project', None)
    if project_id is not None:

        try:
            # Query authz for the project details.
            response = get_sciauthz_project(project_id)
            project = response.json()

            # Add the title and description to the context.
            context['project'] = project_id
            context['project_title'] = project.get('title', None)
            context['project_description'] = project.get('description', None)
            context['project_icon_url'] = project.get('icon_url', None)

        except (requests.ConnectionError, ValueError):

            logger.error("[SCIAUTH][ERROR][auth] - SciAuthZ project lookup failed")

            # TODO Remove default static data and implement error handling
            context['project_title'] = '[project title]'
            context['project_icon_url'] = 'https://maxcdn.icons8.com/Share/icon/User_Interface//ios_application_placeholder1600.png'
            context['project_description'] = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. ' \
                                             'Suspendisse ipsum nisl, feugiat non nunc vitae, tempor congue libero. ' \
                                             'Morbi condimentum commodo ipsum a pellentesque. Vestibulum ullamcorper ' \
                                             'ornare lobortis. Morbi a eleifend leo. Aliquam sed diam.'

    else:
        logger.debug("[SCIAUTH][DEBUG][auth] - No project identifier passed")

    return render(request, 'login/auth.html', context)


def callback_handling(request):
    """
    Callback from Auth0

    This endpoint is called by auth0 with a code that lets us know the user logged into their Identity Provider successfully.
    We need to use the code to gather the user information from Auth0 and establish the DBMI_JWT cookie.
    """

    logger.debug("[SCIAUTH][DEBUG][callback_handling] - Call returned from Auth0.")

    # This is a code passed back from Auth0 that is used to retrieve a token (Which is used to retrieve user info).
    code = request.GET.get('code', '')

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

    # We're saving all user information into the session
    request.session['profile'] = user_info
    user = django_auth.authenticate(**user_info)

    # If everything is good and we have the user info we can proceed.
    if user:
        # Log the user into the SciAuth Django App.
        login(request, user)

        # Redirect the user to the page they originally requested.
        redirect_url = request.GET.get("next", settings.AUTH0_SUCCESS_URL)

        # Check for a success url. Use substring matching due to Django/Auth0/etc mangling the kv pairs
        matches = [value for key, value in request.GET.items() if 'success_url' in key.lower()]
        if len(matches):

            # Get it.
            success_url = matches[0]
            logger.debug("[SCIAUTH][DEBUG][callback_handling] - Found success URL: " + success_url)

            # Append it to the redirect.
            url_parts = list(parse.urlparse(redirect_url))
            query = dict(parse.parse_qsl(url_parts[4]))
            query.update({"success_url": success_url})
            url_parts[4] = parse.urlencode(query)
            redirect_url = parse.urlunparse(url_parts)

        response = redirect(redirect_url)

        # Set the JWT into a cookie in the response.
        response.set_cookie('DBMI_JWT', token_info['id_token'], domain=settings.COOKIE_DOMAIN, httponly=True)

        logger.debug("[SCIAUTH][DEBUG][callback_handling] - User logged in, returning.")

        return response

    return HttpResponse(status=400)

@user_auth_and_jwt
def logout_view(request):
    """
    User logout

    This endpoint logs out the user session from the SciAuth Django app.
    """
    logout(request)
    return redirect(settings.AUTH0_LOGOUT_URL)

@user_auth_and_jwt
def landingpage(request):
    return render(request, 'login/landingpage.html')
