import os

app_dir = os.path.abspath(os.path.dirname(__file__))

class BaseConfig:
    pass
    # SECRET_KEY = os.environ.get('SECRET_KEY') or 'A SECRET KEY'
    # SQLALCHEMY_TRACK_MODIFICATIONS = False

class DevelopementConfig(BaseConfig):
    DEBUG = True
    DATABASE_URI = os.environ.get('DEVELOPMENT_DATABASE_URI') or \
        'tcp:127.0.0.1:6640'


class TestingConfig(BaseConfig):
    DEBUG = True
    DATABASE_URI = os.environ.get('TESTING_DATABASE_URI') or \
	'tcp:127.0.0.1:6640'


class ProductionConfig(BaseConfig):
    DEBUG = False
    DATABASE_URI = os.environ.get('PRODUCTION_DATABASE_URI') or \
	'tcp:127.0.0.1:6640'