from flask import Flask
import os, config
from ovs_vsctl import VSCtl

# создание экземпляра приложения
app = Flask(__name__)
app.config.from_object(os.environ.get('FLASK_ENV') or 'config.DevelopementConfig')

# инициализирует расширения
uri = app.config['DATABASE_URI'].split(':')
vsctl = VSCtl(str(uri[0]), str(uri[1]), int(uri[2]))

from . import views