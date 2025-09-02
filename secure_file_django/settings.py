from pathlib import Path
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Build paths inside the project
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "fallback-secret-key")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv("DJANGO_DEBUG", "False") == "True"

# Allowed hosts (add your domain/IP here)
ALLOWED_HOSTS = os.getenv("DJANGO_ALLOWED_HOSTS", "127.0.0.1,localhost").split(",")


# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Your apps
    'fileapp',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.middleware.http.ConditionalGetMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'secure_file_django.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / "templates"],  # Add templates folder if needed
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

WSGI_APPLICATION = 'secure_file_django.wsgi.application'


# Database (use PostgreSQL/MySQL in production)
DATABASES = {
    'default': {
        'ENGINE': os.getenv("DB_ENGINE", "django.db.backends.sqlite3"),
        'NAME': os.getenv("DB_NAME", BASE_DIR / "db.sqlite3"),
        'USER': os.getenv("DB_USER", ""),
        'PASSWORD': os.getenv("DB_PASSWORD", ""),
        'HOST': os.getenv("DB_HOST", ""),
        'PORT': os.getenv("DB_PORT", ""),
    }
}


# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]


# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True


# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'

# Directory where collectstatic will place files
STATIC_ROOT = BASE_DIR / "staticfiles"

# Additional static files (optional, for dev)
STATICFILES_DIRS = [
    BASE_DIR / "static",
]

# Media files
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / "media"


# Security settings for production
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True
SECURE_SSL_REDIRECT = os.getenv("DJANGO_SECURE_SSL_REDIRECT", "True") == "True"
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"


# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
