[![Django CI](https://github.com/dsk1ra/okta-dashboard-back/actions/workflows/django.yml/badge.svg)](https://github.com/dsk1ra/okta-dashboard-back/actions/workflows/django.yml)
[![Docker CI](https://github.com/dsk1ra/okta-dashboard-back/actions/workflows/docker.yml/badge.svg)](https://github.com/dsk1ra/okta-dashboard-back/actions/workflows/docker.yml)


Important:
To run the app via Docker, add an .env file with the following structure:
Important:
To run the app via Docker, add an .env file with the following structure:

```env
# Security
DJANGO_SECRET_KEY='your-django-secret-key'
DEBUG=True
ALLOWED_HOSTS='localhost,127.0.0.1'
DJANGO_SETTINGS_MODULE='OktaDashboardBackend.settings'

# MongoDB settings
MONGO_HOST='mongodb'  # Use 'mongodb' for Docker, 'localhost' for local dev
MONGO_PORT='27017'
MONGO_DB_NAME='OktaDashboardDB'
MONGO_USER='admin'
MONGO_PASSWORD='your-mongo-password'
MONGO_AUTH_SOURCE='admin'

# Redis settings
REDIS_PASSWORD='your-redis-password'

# Okta API/Logs Settings (used by traffic_analysis)
OKTA_DOMAIN='https://your-domain.okta.com'
OKTA_CLIENT_ID='your-client-id'
OKTA_REDIRECT_URI='http://127.0.0.1:8000/okta/callback'
OKTA_SCOPES='openid profile email'
OKTA_AUTHORIZATION_ENDPOINT='https://your-domain.okta.com/oauth2/v1/authorize'
OKTA_TOKEN_ENDPOINT='https://your-domain.okta.com/oauth2/v1/token'
OKTA_USER_INFO_ENDPOINT='https://your-domain.okta.com/oauth2/v1/userinfo'
OKTA_ORG_URL='https://your-domain.okta.com'
OKTA_CLIENT_SECRET='your-client-secret'
OKTA_INTROSPECTION_ENDPOINT='https://your-domain.okta.com/oauth2/v1/introspect'

# Okta Auth Settings (used by okta_auth)
OKTA_AUTHORIZATION_ORG_URL='https://your-auth-domain.okta.com'
OKTA_AUTHORIZATION_CLIENT_ID='your-auth-client-id'
OKTA_AUTHORIZATION_CLIENT_SECRET='your-auth-client-secret'

# Security options
CSRF_COOKIE_SECURE=False
SESSION_COOKIE_SECURE=False
SECURE_SSL_REDIRECT=False
SECURE_CONTENT_TYPE_NOSNIFF=False