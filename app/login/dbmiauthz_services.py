import requests
import logging
from furl import furl

from dbmiauth import settings

logger = logging.getLogger(__name__)


def get_dbmiauthz_project(project):

    logger.debug("[dbmiauth][DEBUG][dbmiauthz_services] - Request project info for: " + project)

    # Build the url.
    f = furl(settings.DBMIAUTHZ_URL)
    f.path.add('project')

    # Set the data for the request.
    data = {'project': project}

    try:
        # Make the request.
        response = requests.post(f.url, data=data)
    except Exception as e:
        logger.error("[DBMIAUTH][ERROR][sciauthz_services] - Exception: " + str(e))
        raise

    return response
