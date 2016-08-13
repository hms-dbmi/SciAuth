from django.contrib.auth.models import User


class Auth0Authentication(object):

    def authenticate(self, **token_dictionary):
        print("ATTEMPTING TO AUTHENTICATE USER")
        try:
            user = User.objects.get(email=token_dictionary["email"])
        except User.DoesNotExist:
            print("User not found, creating.")
            user = User(username=token_dictionary["email"])
            user.is_staff = True
            user.is_superuser = True
            user.save()
        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None


