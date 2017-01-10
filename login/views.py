from django.shortcuts import render, redirect
from stronghold.decorators import public
from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib.auth import login, logout
from django.contrib import auth as django_auth

import requests
import json


@public
def auth(request):
    if request.user.is_authenticated() and request.COOKIES.get("DBMI_JWT", None) is not None:
        redirect_url = request.GET.get("next", settings.AUTH0_SUCCESS_URL)
        return redirect(redirect_url)

    return render(request, 'login/auth.html', {'auth0_callback_url': settings.AUTH0_CALLBACK_URL})

@public
def callback_handling(request):
    """
        Default handler to login user
        :param request: HttpRequest
        """
    code = request.GET.get('code', '')
    json_header = {'content-type': 'application/json'}
    token_url = 'https://%s/oauth/token' % settings.AUTH0_DOMAIN

    token_payload = {
        'client_id': settings.AUTH0_CLIENT_ID,
        'client_secret': settings.AUTH0_SECRET,
        'redirect_uri': settings.AUTH0_CALLBACK_URL,
        'code': code,
        'grant_type': 'authorization_code'
    }

    token_info = requests.post(token_url,
                               data=json.dumps(token_payload),
                               headers=json_header).json()

    url = 'https://%s/userinfo?access_token=%s'
    user_url = url % (settings.AUTH0_DOMAIN,
                      token_info.get('access_token', ''))

    user_info = requests.get(user_url).json()

    # We're saving all user information into the session
    request.session['profile'] = user_info
    user = django_auth.authenticate(**user_info)

    if user:
        redirect_url = request.GET.get("next", settings.AUTH0_SUCCESS_URL)
        login(request, user)

        response = redirect(redirect_url)
        response.set_cookie('DBMI_JWT', token_info['id_token'], domain=settings.COOKIE_DOMAIN)
        return response

    return HttpResponse(status=400)


def landingpage(request):
    return render(request, 'login/landingpage.html')


def logout_view(request):
    logout(request)
    return redirect(settings.AUTH0_LOGOUT_URL)
