from django.shortcuts import render, redirect
from django.conf import settings
from django.http import HttpResponse
from django.contrib.auth import login, logout
from django.contrib import auth as django_auth
from pyauth0jwt.auth0authenticate import user_auth_and_jwt

import requests
import json
import logging
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

    return render(request, 'login/auth.html', {'auth0_callback_url': settings.AUTH0_CALLBACK_URL,
                                               'auth0_client_id': settings.AUTH0_CLIENT_ID,
                                               'auth0_domain': settings.AUTH0_DOMAIN})


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
        'client_secret': settings.AUTH0_SECRET,
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
        response = redirect(redirect_url)

        # Set the JWT into a cookie in the response.
        response.set_cookie('DBMI_JWT', token_info['id_token'], domain=settings.COOKIE_DOMAIN)

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
