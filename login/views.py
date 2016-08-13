from django.shortcuts import render, redirect
from stronghold.decorators import public
from django.conf import settings
from django.http import HttpResponse
from django.contrib.auth import login
from django.contrib import auth as django_auth

import requests
import json


@public
def auth(request):
    if request.user.is_authenticated():
        return redirect('/login/landingPage/')

    # auth0info = {
    #     "AUTH0_CLIENT_ID": settings.AUTH0_CLIENT_ID,
    #     "AUTH0_CLIENT_SECRET": settings.AUTH0_CLIENT_SECRET,
    #     "AUTH0_DOMAIN": settings.AUTH0_DOMAIN,
    #     "AUTH0_CALLBACK_URL": settings.AUTH0_CALLBACK_URL,
    # }
    # , {'auth0info': auth0info}

    return render(request, 'login/auth.html')

@public
def callback_handling(request):
    """
        Default handler to login user
        :param request: HttpRequest
        """
    code = request.GET.get('code', '')
    config = get_config()
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
        login(request, user)
        return redirect(config['AUTH0_SUCCESS_URL'])

    return HttpResponse(status=400)


def get_config():
    """ Collects AUTH0_* configurations """
    return {
        'AUTH0_CLIENT_ID': settings.AUTH0_CLIENT_ID,
        'AUTH0_SECRET': settings.AUTH0_SECRET,
        'AUTH0_DOMAIN': settings.AUTH0_DOMAIN,
        'AUTH0_CALLBACK_URL': settings.AUTH0_CALLBACK_URL,
        'AUTH0_SUCCESS_URL': settings.AUTH0_SUCCESS_URL,
    }

def landingpage(request):
    return render(request, 'login/landingpage.html')

