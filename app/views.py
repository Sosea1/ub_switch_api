import subprocess
from app import app
from flask import render_template, request, redirect, url_for, flash, make_response, session
# from .models import User, Post, Category, Feedback, db
# from .forms import ContactForm, LoginForm
from .utils import makeRequest, parse_to_json
from ovs_vsctl import VSCtl
from ovs_vsctl import parser
from app import vsctl


@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"


#----------ovs-------------#
#    выводит схему базы данных OpenVSwitch
@app.route("/ovs/get-schema", methods = ['GET'])
def route_ovs_get_schema():
    return makeRequest('tcp:127.0.0.1:6640', 'get_schema', ['Open_vSwitch']).result
    


#----------ovs-vsctl-------------#
#    выполняет команду ovs-vsctl show
#    выводит схему OpenVSwitch
@app.route("/ovs-vsctl/show", methods = ['GET'])
def route_ovs_vsctl_show():
    result = vsctl.run('show', 'list', 'json')
    result = result.stdout.read().strip()
    return parse_to_json(result)


#    выполняет команду ovs-vsctl add-port `bridge `port`
#   добавляет указанный порт в указанный мост с указанным тегом vlan
@app.route("/ovs-vsctl/add-port")
def route_ovs_vsctl_add_port():
    bridge = request.args.get('bridge')        #берет из строки запроса аргумент `bridge` - мост в который добавить порт
    port = request.args.get('port')             #берет из строки запроса аргумент `port`  - название порта который нужно добавить
    vlan = request.args.get('vlan')             #берет из строки запроса аргумент `vlan`  - тег vlan для порта
    if(bridge == None or port == None):
        return "specify bridge and port"
    if vlan != None:
        result = vsctl.run('add-port '+ bridge+' '+port +' tag='+vlan, 'list', 'json')
    else:
        result = vsctl.run('add-port '+ bridge+' '+port, 'list', 'json')
    return "port "+port+" added to "+bridge


#    выполняет команду ovs-vsctl del-port `bridge `port`
#   удаляет указанный порт из указаного моста
@app.route("/ovs-vsctl/del-port")
def route_ovs_vsctl_del_port():
    bridge = request.args.get('bridge')
    port = request.args.get('port')
    if(bridge == None or port == None):
        return "specify bridge and port"
    result = vsctl.run('del-port '+ bridge+' '+port, 'list', 'json')
    return "port "+port+" deleted from "+bridge



#    выполняет команду ovs-vsctl add-br `bridge`
#   добавляет указанный мост
@app.route("/ovs-vsctl/add-bridge")
def route_ovs_vsctl_add_bridge():
    bridge = request.args.get('bridge')      #берет из строки запроса аргумент `bridge` - название моста
    if(bridge == None):
        return "specify bridge"
    result = vsctl.run('add-br '+ bridge, 'list', 'json')
    return "bridge "+bridge+" has been added"

#    выполняет команду ovs-vsctl del-br `bridge`
#   удаляет указанный мост
@app.route("/ovs-vsctl/del-bridge")
def route_ovs_vsctl_del_bridge():
    bridge = request.args.get('bridge')
    if(bridge == None):
        return "specify bridge"
    result = vsctl.run('del-br '+ bridge, 'list', 'json')
    return "bridge "+bridge+" has been deleted"

#    Пример запроса для выполнения команды linux
#   Запрашиваем версию nftables 
@app.route("/nft/get-version")
def route_nft_get_version():
    result = subprocess.run(["nft", "-v"], capture_output=True, text=True)
    if result.returncode != 0:
        return "The command failed with return code:\n"+result.returncode
    return result.stdout
