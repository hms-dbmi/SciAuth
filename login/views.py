def login(request, template_name='login/login.html'):
    if request.user.is_authenticated():
        return redirect('/login/dashboard/')

    # auth0info = {
    #     "AUTH0_CLIENT_ID": settings.AUTH0_CLIENT_ID,
    #     "AUTH0_CLIENT_SECRET": settings.AUTH0_CLIENT_SECRET,
    #     "AUTH0_DOMAIN": settings.AUTH0_DOMAIN,
    #     "AUTH0_CALLBACK_URL": settings.AUTH0_CALLBACK_URL,
    # }
#, {'auth0info': auth0info}
    return render_to_response('login/login.html', context_instance=RequestContext(request))
