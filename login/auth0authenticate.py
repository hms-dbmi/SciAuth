from django.contrib.auth.models import User

from django.contrib.auth import logout
from django.shortcuts import redirect
from django.conf import settings

import logging
logger = logging.getLogger(__name__)


def user_auth_and_jwt(function):
    def wrap(request, *args, **kwargs):

        # User is both logged into this app and via JWT.
        if request.user.is_authenticated() and request.COOKIES.get("DBMI_JWT", None) is not None:
            return function(request, *args, **kwargs)
        # User has a JWT session open but not a Django session. Start a Django session and continue the request.
        elif not request.user.is_authenticated() and request.COOKIES.get("DBMI_JWT", None) is not None:
            jwt_login(request)
            return function(request, *args, **kwargs)
        # User doesn't pass muster, throw them to the login app.
        else:
            logout(request)
            response = redirect(settings.LOGIN_URL)
            response.delete_cookie('DBMI_JWT', domain=settings.COOKIE_DOMAIN)
            return response
    wrap.__doc__ = function.__doc__
    wrap.__name__ = function.__name__
    return wrap


class Auth0Authentication(object):

    def authenticate(self, **token_dictionary):
        """
        Custom authenticate method for logging a user into the SciAuth App via their e-mail address.

        :param token_dictionary:
        :return:
        """

        logger.debug("[SCIAUTH][DEBUG][authenticate] - Attempting to find user record.")

        try:
            user = User.objects.get(username=token_dictionary["email"])
        except User.DoesNotExist:
            logger.info("User not found, creating.")

            user = User(username=token_dictionary["email"], email=token_dictionary["email"])
            user.save()
        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None


