#!/bin/sh
cd /app/user_service
python manage.py makemigrations user --noinput
python manage.py migrate --noinput
python manage.py collectstatic --noinput
exec "$@"