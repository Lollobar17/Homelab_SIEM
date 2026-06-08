"""
WSGI entrypoint for Gunicorn / production deployments.
Starts background collectors before serving HTTP.
"""
from app import app, bootstrap_background_services

bootstrap_background_services()
