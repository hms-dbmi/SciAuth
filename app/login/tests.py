import mock
import requests
from urllib import parse
from httmock import all_requests, urlmatch, HTTMock

from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model, get_user

from dbmiauth import settings
from .views import auth, logout_view, landingpage
from .dbmiauthz_services import get_dbmiauthz_project

"""
Declare data to mimic that being consumed by the app
"""


class TestUser:
    first_name = 'Test'
    last_name = 'User'
    email = 'testuser@email.com'
    token = 'WIUHDI&WHQDBKbIYWGD^GUQG^DG&wdydwg^@@Ejdh37364BQWKDBKWDU##B@@9wUDBi&@GiYWBD'


class TestProject:
    identifier = 'autism'
    icon_url = 'https://maxcdn.icons8.com/Share/icon/User_Interface//ios_application_placeholder1600.png'
    title = 'PPM Autism'
    description = 'This is a sample description of the autism project to be shown at the auth screen'


class LoginTestCase(TestCase):

    def setUp(self):

        # Create a user.
        self.user = self.user = get_user_model().objects.create(email=TestUser.email, username=TestUser.email)
        self.user.backend = 'django.contrib.auth.backends.ModelBackend'
        self.user.save()

        # Prepare a client.
        self.client = Client()

    def test_auth(self):

        # Prepare the request.
        response = self.client.get(reverse(auth))

        # Check the response.
        self.assertEqual(response.status_code, 200)

    def test_auth_login_no_jwt(self):

        # Login.
        self.client.force_login(self.user)

        # Prepare the request.
        response = self.client.get(reverse(auth), data={'project': TestProject.identifier, 'next': reverse(landingpage)})

        # Check the response.
        self.assertNotEqual(response.status_code, 302, "Redirect occurred without valid JWT cookie")
        self.assertTrue(response.status_code, 200)

    def test_auth_redirect_invalid_jwt(self):

        # Login.
        self.client.cookies['DBMI_JWT'] = TestUser.token
        self.client.force_login(self.user)

        # Prepare the request.
        response = self.client.get(reverse(auth),
                                   data={'project': TestProject.identifier, 'next': reverse(landingpage)},
                                   follow=True)

        # Build the target url (auth view with landingpage as next). Auth0 specification is set to 'testserver'
        target_url = settings.AUTHENTICATION_LOGIN_URL + '?next=http://testserver' + reverse(landingpage)

        # Check the response.
        self.assertRedirects(response,
                             status_code=302,
                             target_status_code=200,
                             expected_url=target_url,
                             msg_prefix="Redirect failed despite invalid JWT")

    @mock.patch('jwt.decode', new=mock.MagicMock(return_value=TestUser.token))
    def test_auth_redirect(self):

        # Login.
        self.client.cookies['DBMI_JWT'] = TestUser.token
        self.client.force_login(self.user)

        # Prepare the request.
        response = self.client.get(reverse(auth),
                                   data={'project': TestProject.identifier, 'next': reverse(landingpage)},
                                   follow=True)

        # Check the response.
        self.assertRedirects(response,
                             status_code=302,
                             target_status_code=200,
                             expected_url=reverse(landingpage),
                             msg_prefix="Redirect failed despite proper validation")


class LoginViewTestCase(TestCase):

    def test_auth_project_error(self):

        # Setup the mock.
        @all_requests
        def mock_authz(url, request):

            # Parse the request.
            content = parse.parse_qs(request.body)

            # Check for project.
            self.assertIsNotNone(content['project'])
            self.assertEqual(content['project'][0], TestProject.identifier)

            return {'status_code': 500}

        with HTTMock(mock_authz):

            # Prepare the request.
            response = self.client.get(reverse(auth), data={'project': TestProject.identifier})

            # Ensure it loads still.
            self.assertEqual(response.status_code, 200)

    def test_auth_project_title_description_icon(self):

        # Setup the mock.
        @all_requests
        def mock_authz(url, request):

            # Parse the request.
            content = parse.parse_qs(request.body)

            # Check for project.
            self.assertIsNotNone(content['project'])
            self.assertEqual(content['project'][0], TestProject.identifier)

            return {'status_code': 200,
                    'content': {
                        'title': TestProject.title,
                        'description': TestProject.description,
                        'icon_url': TestProject.icon_url,
                        }
                    }

        with HTTMock(mock_authz):

            # Prepare the request.
            response = self.client.get(reverse(auth), data={'project': TestProject.identifier})

            # Check the response.
            self.assertContains(response, 'class="project-panel panel"',
                                msg_prefix='Auth view does not contain the project panel')
            self.assertContains(response, TestProject.title,
                                msg_prefix='Auth view does not contain the project title')
            self.assertContains(response, TestProject.description,
                                msg_prefix='Auth view does not contain the project description')
            self.assertContains(response, 'src="' + TestProject.icon_url + '"',
                                msg_prefix='Auth view does not contain the project icon url')

    def test_auth_project_title_description(self):

        # Setup the mock.
        @all_requests
        def mock_authz(url, request):

            # Parse the request.
            content = parse.parse_qs(request.body)

            # Check for project.
            self.assertIsNotNone(content['project'])
            self.assertEqual(content['project'][0], TestProject.identifier)

            return {'status_code': 200,
                    'content': {
                        'title': TestProject.title,
                        'description': TestProject.description,
                        }
                    }

        with HTTMock(mock_authz):

            # Prepare the request.
            response = self.client.get(reverse(auth), data={'project': TestProject.identifier})

            # Check the response.
            self.assertContains(response, 'class="project-panel panel"',
                                msg_prefix='Auth view does not contain the project panel')
            self.assertContains(response, TestProject.title,
                                msg_prefix='Auth view does not contain the project title')
            self.assertContains(response, TestProject.description,
                                msg_prefix='Auth view does not contain the project description')
            self.assertNotContains(response, 'src="' + TestProject.icon_url + '"',
                                msg_prefix='Auth view still contains the project icon url')

    def test_auth_project_title_icon(self):

        # Setup the mock.
        @all_requests
        def mock_authz(url, request):

            # Parse the request.
            content = parse.parse_qs(request.body)

            # Check for project.
            self.assertIsNotNone(content['project'])
            self.assertEqual(content['project'][0], TestProject.identifier)

            return {'status_code': 200,
                    'content': {
                        'title': TestProject.title,
                        'icon_url': TestProject.icon_url,
                        }
                    }

        with HTTMock(mock_authz):

            # Prepare the request.
            response = self.client.get(reverse(auth), data={'project': TestProject.identifier})

            # Check the response.
            self.assertContains(response, 'class="project-panel panel"',
                                msg_prefix='Auth view does not contain the project panel')
            self.assertContains(response, TestProject.title,
                                msg_prefix='Auth view does not contain the project title')
            self.assertNotContains(response, TestProject.description,
                                msg_prefix='Auth view still contains the project description')
            self.assertContains(response, 'src="' + TestProject.icon_url + '"',
                                msg_prefix='Auth view does not contain the project icon url')

    def test_auth_project_description_icon(self):

        # Setup the mock.
        @all_requests
        def mock_authz(url, request):

            # Parse the request.
            content = parse.parse_qs(request.body)

            # Check for project.
            self.assertIsNotNone(content['project'])
            self.assertEqual(content['project'][0], TestProject.identifier)

            return {'status_code': 200,
                    'content': {
                        'description': TestProject.description,
                        'icon_url': TestProject.icon_url,
                        }
                    }

        with HTTMock(mock_authz):

            # Prepare the request.
            response = self.client.get(reverse(auth), data={'project': TestProject.identifier})

            # Check the response.
            self.assertContains(response, 'class="project-panel panel"',
                                msg_prefix='Auth view does not contain the project panel')
            self.assertNotContains(response, TestProject.title,
                                msg_prefix='Auth view still contains the project title')
            self.assertContains(response, TestProject.description,
                                msg_prefix='Auth view does not contain the project description')
            self.assertContains(response, 'src="' + TestProject.icon_url + '"',
                                msg_prefix='Auth view does not contain the project icon url')

    def test_auth_project_title(self):

        # Setup the mock.
        @all_requests
        def mock_authz(url, request):

            # Parse the request.
            content = parse.parse_qs(request.body)

            # Check for project.
            self.assertIsNotNone(content['project'])
            self.assertEqual(content['project'][0], TestProject.identifier)

            return {'status_code': 200,
                    'content': {
                        'title': TestProject.title,
                        }
                    }

        with HTTMock(mock_authz):

            # Prepare the request.
            response = self.client.get(reverse(auth), data={'project': TestProject.identifier})

            # Check the response.
            self.assertNotContains(response, 'class="project-panel panel"',
                                msg_prefix='Auth view still contains the project panel')
            self.assertContains(response, TestProject.title,
                                msg_prefix='Auth view does not contain the project title')
            self.assertNotContains(response, TestProject.description,
                                msg_prefix='Auth view still contains the project description')
            self.assertNotContains(response, 'src="' + TestProject.icon_url + '"',
                                msg_prefix='Auth view still contains the project icon url')

    def test_auth_project_description(self):

        # Setup the mock.
        @all_requests
        def mock_authz(url, request):

            # Parse the request.
            content = parse.parse_qs(request.body)

            # Check for project.
            self.assertIsNotNone(content['project'])
            self.assertEqual(content['project'][0], TestProject.identifier)

            return {'status_code': 200,
                    'content': {
                        'description': TestProject.description,
                        }
                    }

        with HTTMock(mock_authz):

            # Prepare the request.
            response = self.client.get(reverse(auth), data={'project': TestProject.identifier})

            # Check the response.
            self.assertContains(response, 'class="project-panel panel"',
                                msg_prefix='Auth view does not contain the project panel')
            self.assertNotContains(response, TestProject.title,
                                msg_prefix='Auth view still contains the project title')
            self.assertContains(response, TestProject.description,
                                msg_prefix='Auth view does not contain the project description')
            self.assertNotContains(response, 'src="' + TestProject.icon_url + '"',
                                msg_prefix='Auth view still contains the project icon url')

    def test_auth_project_icon(self):

        # Setup the mock.
        @all_requests
        def mock_authz(url, request):

            # Parse the request.
            content = parse.parse_qs(request.body)

            # Check for project.
            self.assertIsNotNone(content['project'])
            self.assertEqual(content['project'][0], TestProject.identifier)

            return {'status_code': 200,
                    'content': {
                        'icon_url': TestProject.icon_url,
                        }
                    }

        with HTTMock(mock_authz):

            # Prepare the request.
            response = self.client.get(reverse(auth), data={'project': TestProject.identifier})

            # Check the response.
            self.assertNotContains(response, 'class="project-panel panel"',
                                msg_prefix='Auth view still contains the project panel')
            self.assertNotContains(response, TestProject.title,
                                msg_prefix='Auth view still contains the project title')
            self.assertNotContains(response, TestProject.description,
                                msg_prefix='Auth view still contains the project description')
            self.assertNotContains(response, 'src="' + TestProject.icon_url + '"',
                                msg_prefix='Auth view still contains the project icon url')


class SciAuthZServicesTestCase(TestCase):

    def test_dbmiauthz_get_project(self):

        # Setup the mock.
        @all_requests
        def mock_authz(url, request):

            # Parse the request.
            content = parse.parse_qs(request.body)

            # Check for project.
            self.assertIsNotNone(content['project'])
            self.assertEqual(content['project'][0], TestProject.identifier)

            return {'status_code': 200,
                    'content': {
                        'title': TestProject.title,
                        'description': TestProject.description,
                        'icon_url': TestProject.icon_url,
                        }
                    }

        with HTTMock(mock_authz):

            # Make the call.
            response = get_dbmiauthz_project(TestProject.identifier)

            # Form the data.
            project = response.json()

            # Check it.
            self.assertEqual(TestProject.title, project['title'])
            self.assertEqual(TestProject.description, project['description'])
            self.assertEqual(TestProject.icon_url, project['icon_url'])

    def test_dbmiauthz_get_project_invalid(self):

        # Setup the mock.
        @all_requests
        def mock_authz(url, request):

            # Parse the request.
            content = parse.parse_qs(request.body)

            # Check for project.
            self.assertIsNotNone(content['project'])

            return {'status_code': 200,
                    'content': {}
                    }

        with HTTMock(mock_authz):

            # Make the call.
            response = get_dbmiauthz_project('dwahouidhwd')

            # Form the data.
            project = response.json()

            # Check it.
            self.assertDictEqual(project, {})

    def test_dbmiauthz_get_project_invalid_response(self):

        # Setup the mock.
        @all_requests
        def mock_authz(url, request):

            # Parse the request.
            content = parse.parse_qs(request.body)

            # Check for project.
            self.assertIsNotNone(content['project'])

            return {'status_code': 200,
                    'content': {}
                    }

        with HTTMock(mock_authz):

            # Make the call.
            response = get_dbmiauthz_project('dwahouidhwd')

            # Form the data.
            project = response.json()

            # Check it.
            self.assertDictEqual(project, {})

    def test_dbmiauthz_get_project_error(self):

        # Make the call with no mock or intercept.
        with self.assertRaises(requests.ConnectionError):

            get_dbmiauthz_project('dwahouidhwd')


@mock.patch('pyauth0jwt.auth0authenticate.validate_jwt', lambda x: TestUser.token)
class LogoutTestCase(TestCase):

    def setUp(self):

        # Create a user.
        self.user = self.user = get_user_model().objects.create(email=TestUser.email, username=TestUser.email)
        self.user.backend = 'django.contrib.auth.backends.ModelBackend'
        self.user.save()

        # Prepare a client.
        self.client = Client()

        # Login.
        self.client.cookies['DBMI_JWT'] = TestUser.token
        self.client.force_login(self.user)

    def test_logout_view(self):

        # Logout.
        response = self.client.get(reverse(logout_view))

        # Check.
        self.assertRedirects(response, status_code=302,
                             target_status_code=404,
                             expected_url=settings.AUTH0_LOGOUT_URL,
                             msg_prefix='Logout did not redirect user to ' + settings.AUTH0_LOGOUT_URL)

        # See if the user is still logged in.
        user = get_user(self.client)
        self.assertFalse(user.is_authenticated())

        # Ensure user was logged out and session was cleared.
        self.assertEquals(len(self.client.session.items()), 0)


class LandingPageTestCase(TestCase):

    def setUp(self):

        # Create a user.
        self.user = self.user = get_user_model().objects.create(email=TestUser.email, username=TestUser.email)
        self.user.backend = 'django.contrib.auth.backends.ModelBackend'
        self.user.save()

        # Prepare a client.
        self.client = Client()

        # Login.
        self.client.cookies['DBMI_JWT'] = TestUser.token
        self.client.force_login(self.user)

    def test_landing_page_view_auth(self):

        # Make the request.
        response = self.client.get(reverse(landingpage))

        # Build the target url (auth view with landingpage as next). Auth0 specification is set to 'testserver'
        target_url = settings.AUTHENTICATION_LOGIN_URL + '?next=http://testserver' + reverse(landingpage)

        # Check the response.
        self.assertRedirects(response,
                             status_code=302,
                             target_status_code=200,
                             expected_url=target_url,
                             msg_prefix='Unexpected redirect')

    @mock.patch('pyauth0jwt.auth0authenticate.validate_jwt', lambda x: TestUser.token)
    def test_landing_page_view(self):

        # Make the request.
        response = self.client.get(reverse(landingpage))

        # Check the response.
        self.assertEquals(response.status_code, 200, msg='Landing page was unreachable')
