"""
Django settings for OktaDashboardBackend project.
"""

import os
from pathlib import Path
import environ
from mongoengine import connect

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables
env = environ.Env()
environ.Env.read_env(os.path.join(BASE_DIR, ".env"))


# Function to read Docker secrets if available
def get_secret_from_file(filepath, default=None):
	try:
		with open(filepath) as f:
			return f.read().strip()
	except FileNotFoundError:
		return default


# Security settings
SECRET_KEY = get_secret_from_file("/run/secrets/django_secret_key",
								  env("DJANGO_SECRET_KEY", default="unsafe-default-key"))
DEBUG = env.bool("DEBUG", default=False)
ALLOWED_HOSTS = env.list("DJANGO_ALLOWED_HOSTS", default=["localhost", "127.0.0.1", "web"])

# Okta Credentials
OKTA_API_TOKEN = env("OKTA_API_TOKEN", default=None)
OKTA_ORG_URL = env("OKTA_ORG_URL", default=None)
OKTA_CLIENT_ID = env("OKTA_CLIENT_ID", default=None)
OKTA_CLIENT_SECRET = env("OKTA_CLIENT_SECRET", default=None)

# Okta Settings
OKTA_AUTHORIZATION_ENDPOINT = "https://dev-72300026.okta.com/oauth2/v1/authorize"
OKTA_TOKEN_ENDPOINT = "https://dev-72300026.okta.com/oauth2/v1/token"
OKTA_REDIRECT_URI = "http://127.0.0.1:8000/okta/callback"
OKTA_USER_INFO_ENDPOINT = "https://dev-72300026.okta.com/oauth2/v1/userinfo"

# Installed apps - Remove duplicates
INSTALLED_APPS = [
	"django.contrib.admin",
	"django.contrib.auth",
	"django.contrib.contenttypes",
	"django.contrib.sessions",
	"django.contrib.messages",
	"django.contrib.staticfiles",
	'TrafficAnalysis.apps.TrafficanalysisConfig',
	'django_q',

	# Custom apps
	'rest_framework',
]

REST_FRAMEWORK = {
	'DEFAULT_PERMISSION_CLASSES': [
		'rest_framework.permissions.IsAuthenticated',
	],
	'DEFAULT_AUTHENTICATION_CLASSES': [
		'rest_framework.authentication.SessionAuthentication',
		'rest_framework.authentication.BasicAuthentication',
	],
	'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
	'PAGE_SIZE': 10
}

Q_CLUSTER = {
	'name': 'DjangoORM',
	'workers': 4,
	'timeout': 90,
	'retry': 120,
	'queue_limit': 50,
	'bulk': 10,
	'orm': 'default',  # Use Django ORM as the broker
	'catch_up': False,
	'ack_failures': True,
	'max_attempts': 3,
}

# Middleware
MIDDLEWARE = [
	"django_prometheus.middleware.PrometheusBeforeMiddleware",
	"django_prometheus.middleware.PrometheusAfterMiddleware",
	"django.middleware.security.SecurityMiddleware",
	"django.contrib.sessions.middleware.SessionMiddleware",
	"django.middleware.common.CommonMiddleware",
	"django.middleware.csrf.CsrfViewMiddleware",
	"django.contrib.auth.middleware.AuthenticationMiddleware",
	"django.contrib.messages.middleware.MessageMiddleware",
	"django.middleware.clickjacking.XFrameOptionsMiddleware",
	"whitenoise.middleware.WhiteNoiseMiddleware",
]

# Root URL configuration
ROOT_URLCONF = "OktaDashboardBackend.urls"
WSGI_APPLICATION = "OktaDashboardBackend.wsgi.application"

# MongoDB Configuration
MONGODB_SETTINGS = {
	"db": env("MONGO_DB_NAME", default="OktaDashboardDB"),
	"host": env("MONGO_HOST", default="localhost"),
	"port": env.int("MONGO_PORT", default=27017),
	"username": env("MONGO_USER", default=None),  # Make sure these are set
	"password": env("MONGO_PASSWORD", default=None),
	"authentication_source": env("MONGO_AUTH_SOURCE", default="admin"),
}

# Update the connection code to handle authentication properly
if MONGODB_SETTINGS["username"] and MONGODB_SETTINGS["password"]:
	connect(
		db=MONGODB_SETTINGS["db"],
		host=MONGODB_SETTINGS["host"],
		port=MONGODB_SETTINGS["port"],
		username=MONGODB_SETTINGS["username"],
		password=MONGODB_SETTINGS["password"],
		authentication_source=MONGODB_SETTINGS["authentication_source"],
	)
else:
	# Connect without authentication for local development
	connect(
		db=MONGODB_SETTINGS["db"],
		host=MONGODB_SETTINGS["host"],
		port=MONGODB_SETTINGS["port"],
	)

# Database
DATABASES = {
	'default': {
		'ENGINE': env("DJANGO_DB_ENGINE", default="django.db.backends.sqlite3"),
		'NAME': env("DJANGO_DB_NAME", default=str(BASE_DIR / 'db.sqlite3')),
	}
}

# Templates
TEMPLATES = [
	{
		"BACKEND": "django.template.backends.django.DjangoTemplates",
		"DIRS": [BASE_DIR / "templates"],
		"APP_DIRS": True,
		"OPTIONS": {
			"context_processors": [
				"django.template.context_processors.debug",
				"django.template.context_processors.request",
				"django.template.context_processors.static",
				"django.contrib.auth.context_processors.auth",
				"django.contrib.messages.context_processors.messages",
			],
		},
	},
]

# Password validation
AUTH_PASSWORD_VALIDATORS = [
	{"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
	{"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
	{"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
	{"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# Localization settings
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_L10N = True
USE_TZ = True

# Static and media files
STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "TrafficAnalysis/static"]
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"
WHITENOISE_AUTOREFRESH = env.bool("DJANGO_WHITENOISE_AUTOREFRESH", default=True)
WHITENOISE_USE_FINDERS = True
WHITENOISE_MANIFEST_STRICT = False
WHITENOISE_ROOT = BASE_DIR / "staticfiles"
STATIC_ROOT = BASE_DIR / "staticfiles"

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

# Security settings
CSRF_COOKIE_SECURE = env.bool("CSRF_COOKIE_SECURE", default=False)
SESSION_COOKIE_SECURE = env.bool("SESSION_COOKIE_SECURE", default=False)
SECURE_SSL_REDIRECT = env.bool("SECURE_SSL_REDIRECT", default=False)
SECURE_CONTENT_TYPE_NOSNIFF = env.bool("SECURE_CONTENT_TYPE_NOSNIFF", default=True)
X_FRAME_OPTIONS = "DENY"

# Login URL for redirecting unauthenticated users
LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/dashboard/'
LOGOUT_REDIRECT_URL = '/login/'

# Logging configuration
LOGGING = {
	'version': 1,
	'disable_existing_loggers': False,
	"formatters": {
		"verbose": {
			"format": "{name} {levelname} {asctime} {module} {process:d} {thread:d} {message}",
			"style": "{",
		},
		"simple": {
			"format": "{levelname} {message} {asctime}",
			"style": "{",
		},
	},
	'handlers': {
		'file': {
			'level': 'DEBUG',
			'class': 'logging.FileHandler',
			'formatter': 'verbose',
			'filename': os.path.join(BASE_DIR, 'logs', 'django.log'),
		},
		'console': {
			'level': 'DEBUG',
			'formatter': 'simple',
			'class': 'logging.StreamHandler',
		},
	},
	'loggers': {
		'django': {
			'handlers': ['file', 'console'],
			'level': 'INFO',
			'propagate': True,
		},
		'okta': {
			'handlers': ['file', 'console'],
			'level': 'DEBUG',
			'propagate': True,
		},
		'okta_auth': {
			'handlers': ['file', 'console'],
			'level': 'DEBUG',
			'propagate': True,
		},
	},
}

# Ensure logs directory exists
LOGS_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOGS_DIR, exist_ok=True)
