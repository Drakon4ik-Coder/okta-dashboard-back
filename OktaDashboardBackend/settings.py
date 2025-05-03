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
OKTA_AUTHORIZATION_ENDPOINT = env("OKTA_AUTHORIZATION_ENDPOINT", 
                               default=f"{OKTA_ORG_URL}/oauth2/v1/authorize" if OKTA_ORG_URL else None)
OKTA_TOKEN_ENDPOINT = env("OKTA_TOKEN_ENDPOINT", 
                         default=f"{OKTA_ORG_URL}/oauth2/v1/token" if OKTA_ORG_URL else None)
OKTA_REDIRECT_URI = env("OKTA_REDIRECT_URI", default="http://127.0.0.1:8000/okta/callback")
OKTA_USER_INFO_ENDPOINT = env("OKTA_USER_INFO_ENDPOINT", 
                             default=f"{OKTA_ORG_URL}/oauth2/v1/userinfo" if OKTA_ORG_URL else None)
OKTA_SCOPES = env("OKTA_SCOPES", default="openid profile email okta.users.read okta.logs.read okta.apps.read")

# Zero Trust Authentication Settings
TOKEN_REVALIDATION_INTERVAL = 300  # Validate tokens every 5 minutes
MIN_DEVICE_TRUST_LEVEL = 1  # Minimum device trust level (0-3)
DEVICE_TRUST_SCORE_TTL = 86400  # Device trust score validity (24 hours)
RISK_THRESHOLD_IP_CHANGE = 'medium'  # Risk level for IP changes
RISK_THRESHOLD_INACTIVE_TIME = 1800  # 30 minutes inactivity threshold
RISK_THRESHOLD_SUSPICIOUS = 'high'  # Threshold for suspicious activity

# Zero Trust Session Security Settings
SECURE_SESSION_IDLE_TIMEOUT = 1800  # 30 minutes idle timeout
SECURE_SESSION_ABSOLUTE_TIMEOUT = 28800  # 8 hours max session time
SECURE_SESSION_ROTATE_AFTER = 3600  # Rotate session hourly
SECURE_SESSION_ENFORCE_SINGLE = True  # Only allow one active session per user
SECURE_SESSION_GRACE_PERIOD = 60  # Grace period for session enforcement

# API Authorization Settings
DEFAULT_API_SCOPE = 'okta.dashboard.read'  # Default scope for API access
API_PERMISSIONS = {
    # Format: 'endpoint_pattern': ['required_scope1', 'required_scope2']
    '/api/admin/': ['okta.dashboard.admin'],
    '/api/users/': ['okta.dashboard.users.read', 'okta.dashboard.admin'],
    '/api/logs/': ['okta.dashboard.logs.read', 'okta.dashboard.admin'],
    '/api/settings/': ['okta.dashboard.admin'],
    '/api/analytics/': ['okta.dashboard.analytics.read', 'okta.dashboard.admin'],
    '/api/v1/forensics/': {
        'GET': ['okta.dashboard.forensics.read', 'okta.dashboard.admin'],
        'POST': ['okta.dashboard.forensics.write', 'okta.dashboard.admin'],
    }
}

# Installed apps - Remove duplicates
INSTALLED_APPS = [
	"django.contrib.admin",
	"django.contrib.auth",
	"django.contrib.contenttypes",
	"django.contrib.sessions",
	"django.contrib.messages",
	"django.contrib.staticfiles",
	'traffic_analysis.apps.TrafficAnalysisConfig',  # Updated to use the new app
	'django_q',
	'drf_yasg',
	# Custom apps
	'rest_framework',
	'authentication',  # Add the new authentication app
	
	# Performance optimizations
	'django_prometheus',
	'login_tracking',
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
	'PAGE_SIZE': 10,
	# Performance optimizations for REST
	'DEFAULT_RENDERER_CLASSES': [
		'rest_framework.renderers.JSONRenderer',
	] if not DEBUG else [
		'rest_framework.renderers.JSONRenderer',
		'rest_framework.renderers.BrowsableAPIRenderer',
	],
	'DEFAULT_THROTTLE_CLASSES': [
		'rest_framework.throttling.AnonRateThrottle',
		'rest_framework.throttling.UserRateThrottle',
	],
	'DEFAULT_THROTTLE_RATES': {
		'anon': '100/day',
		'user': '1000/day',
	},
}

# Cache settings
CACHES = {
    'default': {
        'BACKEND': env("CACHE_BACKEND", default='django.core.cache.backends.locmem.LocMemCache'),
        'LOCATION': env("CACHE_LOCATION", default='okta-dashboard-cache'),
        'TIMEOUT': env.int("CACHE_TIMEOUT", default=300),  # 5 minutes default
        'OPTIONS': {
            'MAX_ENTRIES': 1000,
            'CLIENT_CLASS': env("CACHE_CLIENT_CLASS", default=None),
        }
    }
}

# Session cache settings
SESSION_CACHE_ALIAS = "default"
SESSION_ENGINE = env("SESSION_ENGINE", default='django.contrib.sessions.backends.db')

# Q_CLUSTER optimized for better performance
Q_CLUSTER = {
	'name': 'DjangoORM',
	'workers': env.int("Q_WORKERS", default=4),
	'timeout': 90,
	'retry': 120,
	'queue_limit': 50,
	'bulk': 10,
	'orm': 'default',  # Use Django ORM as the broker
	'catch_up': False,
	'ack_failures': True,
	'max_attempts': 3,
	'compress': True,  # Compress large data for task storage
	'sync': env.bool("Q_SYNC", default=False),  # Set to True for debugging
	'guard_cycle': 60,  # Check worker health every minute
}

# Middleware - order matters for performance
MIDDLEWARE = [
	# Metrics should be first and last for accurate measurement
	"django_prometheus.middleware.PrometheusBeforeMiddleware",
	
	"django.middleware.security.SecurityMiddleware",
	"whitenoise.middleware.WhiteNoiseMiddleware",  # Static file handling early
	
	# Custom security headers middleware
	"core.middleware.security_headers.SecurityHeadersMiddleware",
	
	# Session middleware
	"django.contrib.sessions.middleware.SessionMiddleware",
	
	# Performance oriented middleware
	"django.middleware.gzip.GZipMiddleware",  # Compress responses
	
	# Common middleware
	"django.middleware.common.CommonMiddleware",
	"django.middleware.csrf.CsrfViewMiddleware",
	
	# Authentication middleware must come before our custom auth middlewares
	"django.contrib.auth.middleware.AuthenticationMiddleware",
	
	# Zero Trust authentication and authorization middlewares
	# These must come after Django's AuthenticationMiddleware so request.user is available
	"authentication.middleware.secure_session.SecureSessionMiddleware",  # Zero Trust session management
	"authentication.middleware.continuous_auth.ContinuousAuthMiddleware",  # Continuous validation
	"authentication.middleware.api_authorization.APIAuthorizationMiddleware",  # Least privilege
	
	"django.contrib.messages.middleware.MessageMiddleware",
	"django.middleware.clickjacking.XFrameOptionsMiddleware",
	
	# Metrics middleware last
	"django_prometheus.middleware.PrometheusAfterMiddleware",
	'django.contrib.auth.middleware.AuthenticationMiddleware',
	'login_tracking.middleware.LoginTimingMiddleware',
	'django_prometheus.middleware.PrometheusAfterMiddleware',
]

# Root URL configuration
ROOT_URLCONF = "OktaDashboardBackend.urls"
WSGI_APPLICATION = "OktaDashboardBackend.wsgi.application"

# MongoDB Configuration with optimized connection settings
MONGODB_SETTINGS = {
	"db": env("MONGO_DB_NAME", default="OktaDashboardDB"),
	"host": env("MONGO_HOST", default="localhost"),
	"port": env.int("MONGO_PORT", default=27017),
	"username": env("MONGO_USER", default=None),
	"password": env("MONGO_PASSWORD", default=None),
	"authentication_source": env("MONGO_AUTH_SOURCE", default="admin"),
	# Connection optimization settings
	"maxPoolSize": env.int("MONGO_MAX_POOL_SIZE", default=100),
	"minPoolSize": env.int("MONGO_MIN_POOL_SIZE", default=10),
	"maxIdleTimeMS": env.int("MONGO_MAX_IDLE_TIME_MS", default=30000),
	"connectTimeoutMS": env.int("MONGO_CONNECT_TIMEOUT_MS", default=10000),
	"socketTimeoutMS": env.int("MONGO_SOCKET_TIMEOUT_MS", default=20000),
	"serverSelectionTimeoutMS": env.int("MONGO_SERVER_SELECTION_TIMEOUT_MS", default=10000),
	"waitQueueTimeoutMS": env.int("MONGO_WAIT_QUEUE_TIMEOUT_MS", default=5000),
}

# Establish MongoDB connection
try:
    connect(
        db=MONGODB_SETTINGS["db"],
        host=MONGODB_SETTINGS["host"],
        port=MONGODB_SETTINGS["port"],
        username=MONGODB_SETTINGS["username"],
        password=MONGODB_SETTINGS["password"],
        authentication_source=MONGODB_SETTINGS.get("authentication_source"),
        maxPoolSize=MONGODB_SETTINGS.get("maxPoolSize"),
        minPoolSize=MONGODB_SETTINGS.get("minPoolSize"),
        connectTimeoutMS=MONGODB_SETTINGS.get("connectTimeoutMS"),
        socketTimeoutMS=MONGODB_SETTINGS.get("socketTimeoutMS"),
        serverSelectionTimeoutMS=MONGODB_SETTINGS.get("serverSelectionTimeoutMS"),
        waitQueueTimeoutMS=MONGODB_SETTINGS.get("waitQueueTimeoutMS"),
    )
except Exception as e:
    import logging
    logger = logging.getLogger('django')
    logger.warning(f"MongoDB connection failed: {e}")

# Database settings - optimized for production
DATABASES = {
	'default': {
		'ENGINE': env("DJANGO_DB_ENGINE", default="django.db.backends.sqlite3"),
		'NAME': env("DJANGO_DB_NAME", default=str(BASE_DIR / 'db.sqlite3')),
        'CONN_MAX_AGE': env.int('DATABASE_CONN_MAX_AGE', default=60),  # 1 minute connection persistence
        'OPTIONS': {
            'timeout': 20,  # SQLite timeout
        } if env("DJANGO_DB_ENGINE", default="django.db.backends.sqlite3") == "django.db.backends.sqlite3" else {},
	}
}

# Templates with optimization
TEMPLATES = [
	{
		"BACKEND": "django.template.backends.django.DjangoTemplates",
		"DIRS": [BASE_DIR / "templates"],
		"APP_DIRS": True if DEBUG else False,  # Only use APP_DIRS directly in debug mode
		"OPTIONS": {
			"context_processors": [
				"django.template.context_processors.debug",
				"django.template.context_processors.request",
				"django.template.context_processors.static",
				"django.contrib.auth.context_processors.auth",
				"django.contrib.messages.context_processors.messages",
				"core.context_processors.security.nonce_processor",  # Add nonce to all templates
			],
		},
	},
]

# Add loaders only in production mode
if not DEBUG:
    TEMPLATES[0]['OPTIONS']['loaders'] = [
        ('django.template.loaders.cached.Loader', [
            'django.template.loaders.filesystem.Loader',
            'django.template.loaders.app_directories.Loader',
        ]),
    ]
    # Make sure APP_DIRS is False in production
    TEMPLATES[0]['APP_DIRS'] = False

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

# Static and media files - optimized
STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "traffic_analysis/static"]  # Updated to use new app path
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"
WHITENOISE_AUTOREFRESH = not DEBUG  # Only refresh in development
WHITENOISE_USE_FINDERS = DEBUG  # Only in development
WHITENOISE_MANIFEST_STRICT = not DEBUG  # Strict in production
WHITENOISE_ROOT = BASE_DIR / "staticfiles"
STATIC_ROOT = BASE_DIR / "staticfiles"
WHITENOISE_MAX_AGE = 31536000  # 1 year cache for static files

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

# Security settings - enhanced for production
CSRF_COOKIE_SECURE = env.bool("CSRF_COOKIE_SECURE", default=not DEBUG)
SESSION_COOKIE_NAME = 'okta_dashboard_sessionid'
SESSION_COOKIE_SECURE = env.bool("SESSION_COOKIE_SECURE", default=not DEBUG)
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_SAVE_EVERY_REQUEST = False  # Better performance - don't save every request
SESSION_EXPIRE_AT_BROWSER_CLOSE = False
SESSION_COOKIE_AGE = 86400  # 1 day in seconds

# Additional security headers
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# Login URL for redirecting unauthenticated users
LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/dashboard/'
LOGOUT_REDIRECT_URL = '/login/'

# Logging configuration - optimized for production
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
		"json": {  # JSON formatter for better log processing
            "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(asctime)s %(name)s %(levelname)s %(message)s",
        },
	},
	'filters': {
        'require_debug_true': {
            '()': 'django.utils.log.RequireDebugTrue',
        },
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse',
        },
    },
	'handlers': {
		'file': {
			'level': 'INFO',  # Changed to INFO for production
			'class': 'logging.handlers.RotatingFileHandler',  # Use rotating handler
			'formatter': 'verbose',
			'filename': os.path.join(BASE_DIR, 'logs', 'django.log'),
			'maxBytes': 10485760,  # 10MB
            'backupCount': 10,
		},
		'console': {
			'level': 'INFO',  # Changed to INFO for production
			'formatter': 'simple',
			'class': 'logging.StreamHandler',
			'filters': ['require_debug_true'],
		},
		'json_file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': os.path.join(BASE_DIR, 'logs', 'django.json.log'),
            'maxBytes': 10485760,  # 10MB
            'backupCount': 5,
            'formatter': 'json',
        },
	},
	'loggers': {
		'django': {
			'handlers': ['file', 'console', 'json_file'],
			'level': 'INFO',
			'propagate': True,
		},
		'django.request': {
            'handlers': ['file'],
            'level': 'WARNING',
            'propagate': False,
        },
		'django.security': {
            'handlers': ['file'],
            'level': 'WARNING',
            'propagate': False,
        },
		'okta': {
			'handlers': ['file', 'console'],
			'level': 'INFO',  # Changed to INFO for production
			'propagate': True,
		},
		'okta_auth': {
			'handlers': ['file', 'console'],
			'level': 'INFO',  # Changed to INFO for production
			'propagate': True,
		},
	},
}

# Ensure logs directory exists
LOGS_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOGS_DIR, exist_ok=True)

# Performance tuning
DATA_UPLOAD_MAX_MEMORY_SIZE = 5242880  # 5MB
FILE_UPLOAD_MAX_MEMORY_SIZE = 5242880  # 5MB

# Prometheus metrics
PROMETHEUS_EXPORT_MIGRATIONS = False
