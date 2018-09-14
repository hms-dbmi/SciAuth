FROM python:3.6-alpine3.8 AS builder

# Install dependencies
RUN apk add --update \
    build-base \
    g++ \
    openssl-dev \
    libffi-dev

# Add requirements
ADD requirements.txt /requirements.txt

# Install Python packages
RUN pip install -r /requirements.txt

FROM hmsdbmitc/dbmisvc:3.6-alpine

RUN apk add --no-cache --update \
    bash \
    nginx \
    curl \
    openssl \
    jq \
  && rm -rf /var/cache/apk/*

# Copy pip packages from builder
COPY --from=builder /root/.cache /root/.cache

# Add requirements
ADD requirements.txt /requirements.txt

# Install Python packages
RUN pip install -r /requirements.txt

# Copy app source
COPY /app /app

# Set the build env
ENV DBMI_ENV=prod

# Set app parameters
ENV DBMI_PARAMETER_STORE_PREFIX=dbmi.auth.${DBMI_ENV}
ENV DBMI_PARAMETER_STORE_PRIORITY=true

# App config
ENV DBMI_APP_DOMAIN=authentication.dbmi.hms.harvard.edu

# Load balancing
ENV DBMI_LB=true

# SSL and load balancing
ENV DBMI_SSL=true
ENV DBMI_CREATE_SSL=true
ENV DBMI_SSL_PATH=/etc/nginx/ssl

# Static files
ENV DBMI_STATIC_FILES=true
ENV DBMI_APP_STATIC_URL_PATH=/static
ENV DBMI_APP_STATIC_ROOT=/app/assets

# Healthchecks
ENV DBMI_HEALTHCHECK=true

# Set the name of the app to run
ENV DBMI_APP_WSGI=dbmiauth