#!/usr/bin/env bash
# Exit on error
set -o errexit

# Install production dependencies
pip install -r requirements.txt

# Collect static files for WhiteNoise
python manage.py collectstatic --noinput

# Apply database migrations
python manage.py migrate --noinput

# Seed default categories if not already present
python manage.py seed_categories

# Seed initial campus facilities (Central Library in Block 37, sports, academic, dining)
python manage.py seed_facilities

# Seed default admin and faculty accounts if not already present
python manage.py seed_staff_users

