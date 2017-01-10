from django.contrib.auth.models import User


class Auth0Authentication(object):

    def authenticate(self, **token_dictionary):
        """
        Custom authenticate method for logging a user into the SciAuth App via their e-mail address.

        :param token_dictionary:
        :return:
        """

        print("Attempting to Authenticate User - " + token_dictionary["email"])

        try:
            user = User.objects.get(username=token_dictionary["email"])
        except User.DoesNotExist:
            print("User not found, creating.")

            user = User(username=token_dictionary["email"], email=token_dictionary["email"])
            user.is_staff = True
            user.is_superuser = True
            user.save()
        return user

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None


