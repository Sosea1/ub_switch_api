from flask import Flask
import os, config
try:
    from ovs_vsctl import VSCtl
except Exception as exc:
    print("Отсутствует модуль ovs_vsctl: " + str(exc))

# создание экземпляра приложения
webapi = Flask(__name__)
webapi.config.from_object(os.environ.get('FLASK_ENV') or 'config.DevelopementConfig')

# инициализирует расширения
uri = webapi.config['DATABASE_URI'].split(':')
try:
    vsctl = VSCtl(str(uri[0]), str(uri[1]), int(uri[2]))
except:
    vsctl = NotImplemented


from . import views, simple_interface