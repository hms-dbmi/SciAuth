import os
from setuptools import find_packages, setup

with open(os.path.join(os.path.dirname(__file__), 'README.rst')) as readme:
    README = readme.read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='django-auth0-login',
    version='0.1',
    packages=find_packages(),
    include_package_data=True,
    description='DBMI - Auth0 AuthN App',
    long_description=README,
    author='Michael Tommie McDuffie',
    author_email='michael_mcduffie@hms.harvard.edu',
    install_requires=[
        'django-stronghold',
        'requests',
    ],
)