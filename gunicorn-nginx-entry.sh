#!/bin/bash

/vault/vault auth $ONETIME_TOKEN

DJANGO_SECRET=$(/vault/vault read -field=value $VAULT_PATH/django_secret)
AUTH0_DOMAIN_VAULT=$(/vault/vault read -field=value $VAULT_PATH/auth0_domain)
AUTH0_CLIENT_ID_VAULT=$(/vault/vault read -field=value $VAULT_PATH/auth0_client_id)
AUTH0_SECRET_VAULT=$(/vault/vault read -field=value $VAULT_PATH/auth0_secret)
AUTH0_CALLBACK_URL_VAULT=$(/vault/vault read -field=value $VAULT_PATH/auth0_callback_url)
AUTH0_SUCCESS_URL_VAULT=$(/vault/vault read -field=value $VAULT_PATH/auth0_success_url)
AUTH0_LOGOUT_URL_VAULT=$(/vault/vault read -field=value $VAULT_PATH/auth0_logout_url)
COOKIE_DOMAIN_VAULT=$(/vault/vault read -field=value $VAULT_PATH/cookie_domain)

MYSQL_USERNAME_VAULT=$(/vault/vault read -field=value $VAULT_PATH/mysql_username)
MYSQL_PASSWORD_VAULT=$(/vault/vault read -field=value $VAULT_PATH/mysql_pw)
MYSQL_HOST_VAULT=$(/vault/vault read -field=value $DB_VAULT_PATH/mysql_host)
MYSQL_PORT_VAULT=$(/vault/vault read -field=value $VAULT_PATH/mysql_port)

export SECRET_KEY=$DJANGO_SECRET
export AUTH0_DOMAIN=$AUTH0_DOMAIN_VAULT
export AUTH0_CLIENT_ID=$AUTH0_CLIENT_ID_VAULT
export AUTH0_SECRET=$AUTH0_SECRET_VAULT
export AUTH0_CALLBACK_URL=$AUTH0_CALLBACK_URL_VAULT
export AUTH0_SUCCESS_URL=$AUTH0_SUCCESS_URL_VAULT
export AUTH0_LOGOUT_URL=$AUTH0_LOGOUT_URL_VAULT
export COOKIE_DOMAIN=$COOKIE_DOMAIN_VAULT

export MYSQL_USERNAME=$MYSQL_USERNAME_VAULT
export MYSQL_PASSWORD=$MYSQL_PASSWORD_VAULT
export MYSQL_HOST=$MYSQL_HOST_VAULT
export MYSQL_PORT=$MYSQL_PORT_VAULT

SSL_KEY=$(/vault/vault read -field=value $VAULT_PATH/ssl_key)
SSL_CERT_CHAIN=$(/vault/vault read -field=value $VAULT_PATH/ssl_cert_chain)

echo $SSL_KEY | base64 -d >> /etc/nginx/ssl/server.key
echo $SSL_CERT_CHAIN | base64 -d >> /etc/nginx/ssl/server.crt

cd /SciAuth/

python manage.py migrate

if [ ! -d static ]; then
  mkdir static
fi
python manage.py collectstatic --no-input

/etc/init.d/nginx restart

gunicorn SciAuth.wsgi:application -b 0.0.0.0:8002