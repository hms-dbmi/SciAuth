#!/bin/bash

ALLOWED_HOSTS=$(aws ssm get-parameters --names $PS_PATH.allowed_hosts --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')

DJANGO_SECRET=$(aws ssm get-parameters --names $PS_PATH.django_secret --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
AUTH0_DOMAIN_VAULT=$(aws ssm get-parameters --names $PS_PATH.auth0_domain --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
AUTH0_CLIENT_ID_VAULT=$(aws ssm get-parameters --names $PS_PATH.auth0_client_id --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
AUTH0_SECRET_VAULT=$(aws ssm get-parameters --names $PS_PATH.auth0_secret --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
AUTH0_CALLBACK_URL_VAULT=$(aws ssm get-parameters --names $PS_PATH.auth0_callback_url --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
AUTH0_SUCCESS_URL_VAULT=$(aws ssm get-parameters --names $PS_PATH.auth0_success_url --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
AUTH0_LOGOUT_URL_VAULT=$(aws ssm get-parameters --names $PS_PATH.auth0_logout_url --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
COOKIE_DOMAIN_VAULT=$(aws ssm get-parameters --names $PS_PATH.cookie_domain --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')

MYSQL_USERNAME_VAULT=$(aws ssm get-parameters --names $PS_PATH.mysql_username --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
MYSQL_PASSWORD_VAULT=$(aws ssm get-parameters --names $PS_PATH.mysql_pw --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
MYSQL_HOST_VAULT=$(aws ssm get-parameters --names $PS_PATH.mysql_host --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
MYSQL_PORT_VAULT=$(aws ssm get-parameters --names $PS_PATH.mysql_port --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')

RAVEN_URL=$(aws ssm get-parameters --names $PS_PATH.raven_url --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')

export ALLOWED_HOSTS

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

export RAVEN_URL

export SCIREG_URL=$(aws ssm get-parameters --names $PS_PATH.scireg_url --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
export SCIAUTHZ_URL=$(aws ssm get-parameters --names $PS_PATH.sciauthz_url --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
export AUTHENTICATION_LOGIN_URL=$(aws ssm get-parameters --names $PS_PATH.account_server_url --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')

SSL_KEY=$(aws ssm get-parameters --names $PS_PATH.ssl_key --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
SSL_CERT_CHAIN1=$(aws ssm get-parameters --names $PS_PATH.ssl_cert_chain1 --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
SSL_CERT_CHAIN2=$(aws ssm get-parameters --names $PS_PATH.ssl_cert_chain2 --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')
SSL_CERT_CHAIN3=$(aws ssm get-parameters --names $PS_PATH.ssl_cert_chain3 --with-decryption --region us-east-1 | jq -r '.Parameters[].Value')

SSL_CERT_CHAIN="$SSL_CERT_CHAIN1$SSL_CERT_CHAIN2$SSL_CERT_CHAIN3"

echo $SSL_KEY | base64 -d >> /etc/nginx/ssl/server.key
echo $SSL_CERT_CHAIN | base64 -d >> /etc/nginx/ssl/server.crt

cd /app/

python manage.py migrate

if [ ! -d static ]; then
  mkdir static
fi
python manage.py collectstatic --no-input

/etc/init.d/nginx restart

chown -R www-data:www-data /app

gunicorn SciAuth.wsgi:application -b 0.0.0.0:8002 --user=www-data --group=www-data