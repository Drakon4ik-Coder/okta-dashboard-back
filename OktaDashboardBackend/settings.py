import os
from pathlib import Path
import mongoengine
from mongoengine import connect
import environ

BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables
env = environ.Env()
environ.Env.read_env(os.path.join(BASE_DIR, '.env'))

# Security settings
SECRET_KEY = env('DJANGO_SECRET_KEY')
DEBUG = env('DEBUG')
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
    'whitenoise.middleware.WhiteNoiseMiddleware',

]

# Root URLs and WSGI application
ROOT_URLCONF = "OktaDashboardBackend.urls"
WSGI_APPLICATION = "OktaDashboardBackend.wsgi.application"

# MongoDB Configuration using MongoEngine
MONGODB_NAME = env("MONGO_DB_NAME", default="OktaDashboardDB")
MONGODB_HOST = env("MONGO_HOST", default="localhost")
MONGODB_PORT = env.int("MONGO_PORT", default=27017)
MONGODB_USER = env("MONGO_USER", default=None)
MONGODB_PASSWORD = env("MONGO_PASSWORD", default=None)
MONGODB_AUTH_SOURCE = env("MONGO_AUTH_SOURCE", default="admin")

MONGODB_SETTINGS = {
    'db': env('MONGODB_NAME'),
    'host': env('MONGO_HOST'),
    'port': int(env('MONGO_PORT')),
    'username': env('MONGO_USER'),
    'password': env('MONGO_PASSWORD'),
    'authentication_source': env('MONGO_AUTH_SOURCE'),
}



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
                'django.template.context_processors.static',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = "OktaDashboardBackend.wsgi.application"

# Dummy database configuration to satisfy Django's system requirement
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.dummy' if os.getenv('CI') else 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

# MongoDB connection using MongoEngine
MONGODB_DATABASES = {
    'default': {
        "name": env("MONGO_DB_NAME", default="your_database_name"),
        "host": env("MONGO_HOST", default="localhost"),
        "port": env.int("MONGO_PORT", default=27017),
        "username": env("MONGO_USER", default=None),
        "password": env("MONGO_PASSWORD", default=None),
        "authentication_source": env("MONGO_AUTH_SOURCE", default="admin"),
    }
}

# Establish connection to MongoDB
connect(
    db=MONGODB_DATABASES["default"]["name"],
    host=MONGODB_DATABASES["default"]["host"],
    port=MONGODB_DATABASES["default"]["port"],
    username=MONGODB_DATABASES["default"]["username"],
    password=MONGODB_DATABASES["default"]["password"],
    authentication_source=MONGODB_DATABASES["default"].get("authentication_source"),
)

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
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATICFILES_FINDERS = [
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
]
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'
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

