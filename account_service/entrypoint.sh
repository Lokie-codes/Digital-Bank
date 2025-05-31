#!/bin/sh
cd /app/account_service
python manage.py makemigrations accounts --noinput
python manage.py migrate --noinput
python manage.py collectstatic --noinput
exec "$@"
