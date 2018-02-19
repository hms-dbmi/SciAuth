import requests
import json
from django.conf import settings

import logging
logger = logging.getLogger(__name__)


def build_headers_with_jwt(user_jwt):
    return {"Authorization": "JWT " + user_jwt, 'Content-Type': 'application/json'}


def send_confirmation_email(user_jwt, success_url, project):

    # Build the email confirmation link
    send_confirm_email_url = settings.SCIREG_URL + '/api/register/send_confirmation_email/'
    logger.debug("[SciAuth][scireg_services.send_confirmation_email] - Sending user confirmation e-mail to " + send_confirm_email_url)

    # Inform SciReg of the project and where to send the user
    email_confirm_data = {
        'success_url': success_url,
        'project': project,
    }

    return requests.post(send_confirm_email_url, headers=build_headers_with_jwt(user_jwt), data=json.dumps(email_confirm_data))
