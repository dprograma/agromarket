
from .base import *

SECRET_KEY = 'h#9ak=bux2!*7wnc#&mua5%lb0cz(xmakx(c2(0w4f6kl@b2t'

ALLOWED_HOSTS = ['*']

# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

CURRENT_SITE = "http://127.0.0.1:8000"
CLIENT_SITE = "http://127.0.0.1:3000"

# [EMAIL]
MAIL_PORT = 465
MAIL_SERVER = "sandbox.smtp.mailtrap.io"
MAIL_USER = "e4ddb8cd5d0f6e"
MAIL_PASS = "7c789e78d8ef2a"