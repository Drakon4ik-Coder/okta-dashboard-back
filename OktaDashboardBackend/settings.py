import os
from pathlib import Path
import environ
import mongoengine

# Load environment variables
env = environ.Env()
environ.Env.read_env()  # Reads the .env file

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Security settings
SECRET_KEY = env("DJANGO_SECRET_KEY", default="your-default-secret-key")
DEBUG = env.bool("DJANGO_DEBUG", default=False)
ALLOWED_HOSTS = env.list("DJANGO_ALLOWED_HOSTS", default=["localhost", "127.0.0.1", "web"])

# Installed apps
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Custom apps
    "TrafficAnalysis",
]

# Middleware
MIDDLEWARE = [
    'django_prometheus.middleware.PrometheusBeforeMiddleware',
    'django_prometheus.middleware.PrometheusAfterMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# Root URLs and WSGI application
ROOT_URLCONF = "OktaDashboardBackend.urls"
WSGI_APPLICATION = "OktaDashboardBackend.wsgi.application"

# Dummy database (only needed if Django's ORM is used somewhere)
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.dummy',  # Dummy backend as MongoDB doesn't use Django ORM
    }
}

# MongoDB Configuration using MongoEngine
MONGODB_NAME = env("MONGO_DB_NAME", default="okta_dashboard")
MONGODB_HOST = env("MONGO_HOST", default="localhost")
MONGODB_PORT = env.int("MONGO_PORT", default=27017)
MONGODB_USER = env("MONGO_USER", default=None)
MONGODB_PASSWORD = env("MONGO_PASSWORD", default=None)
MONGODB_AUTH_SOURCE = env("MONGO_AUTH_SOURCE", default="admin")

MONGODB_SETTINGS = {
    'db': MONGODB_NAME,
    'host': MONGODB_HOST,
    'port': MONGODB_PORT,
    'username': MONGODB_USER,
    'password': MONGODB_PASSWORD,
    'authentication_source': MONGODB_AUTH_SOURCE,
}

# Connect to MongoDB
mongoengine.connect(**MONGODB_SETTINGS)

# Template settings
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
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
STATICFILES_DIRS = [BASE_DIR / "static"] if DEBUG else []
STATIC_ROOT = BASE_DIR / "staticfiles"

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

# Security settings
CSRF_COOKIE_SECURE = env.bool("CSRF_COOKIE_SECURE", default=False)
SESSION_COOKIE_SECURE = env.bool("SESSION_COOKIE_SECURE", default=False)
SECURE_SSL_REDIRECT = env.bool("SECURE_SSL_REDIRECT", default=False)
SECURE_CONTENT_TYPE_NOSNIFF = env.bool("SECURE_CONTENT_TYPE_NOSNIFF", default=True)
X_FRAME_OPTIONS = "DENY"

# Logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', 'django.log'),
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}

LOGS_DIR = os.path.join(BASE_DIR, 'logs')
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR)

