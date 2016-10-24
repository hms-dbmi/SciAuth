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
    if request.user.is_authenticated():
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
        print(request)
        print(redirect_url)
        response = redirect(redirect_url)
        response.set_cookie('DBMI_JWT', token_info['id_token'])
        return response

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


def forward_launcher(request):
    # Obtain Delegation token.
    delegationTokenUrl = "https://mtmcduffie.auth0.com/delegation"
    json_header = {'content-type': 'application/json'}

    token_payload = {
        'client_id': settings.AUTH0_CLIENT_ID,
        'id_token': request.session['jwt'],
        'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'target':'aiStYYne8qvmVWlZTwANpQ8hVPFIBQqA',
        'scope':'openid',
        'api_type':'app'
    }

    delegation_token = requests.post(delegationTokenUrl,
                  data=json.dumps(token_payload),
                  headers=json_header).json()

    print(delegation_token)

    redirect_response = HttpResponseRedirect('http://localhost:8001/tokenlogin/token_login/')

    redirect_response['Authorization'] = 'Bearer ' + delegation_token["id_token"]

    return redirect_response


def landingpage(request):
    return render(request, 'login/landingpage.html')


def logout_view(request):
    logout(request)
    return redirect(settings.AUTH0_LOGOUT_URL)
