#!/bin/bash -e

# Check for static files
if [[ -n $DBMI_STATIC_FILES ]]; then

    # Make the directory and collect static files
    mkdir -p "$DBMI_APP_STATIC_ROOT"
    python /app/manage.py collectstatic --no-input

fi

