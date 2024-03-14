#!/bin/python3
from flask import Flask, request
from ovs_vsctl import VSCtl
from ovs_vsctl import list_cmd_parser

app = Flask(__name__)

@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"


@app.route("/tests")
def route_tests():
    import Tests.utils
    return Tests.utils.makeRequest('tcp:127.0.0.1:6640', 'get_schema', ['Open_vSwitch']).result


#----------ovs-------------#
#    выводит схему базы данных OpenVSwitch
@app.route("/ovs/get-schema", methods = ['GET'])
def route_ovs_get_schema():
    import Tests.utils
    return Tests.utils.makeRequest('tcp:127.0.0.1:6640', 'get_schema', ['Open_vSwitch']).result


#----------ovs-vsctl-------------#
#    выполняет команду ovs-vsctl show
#    выводит схему OpenVSwitch
@app.route("/ovs-vsctl/show", methods = ['GET'])
def route_ovs_vsctl_show():
    vsctl = VSCtl('tcp', '127.0.0.1', 6640)
    result = vsctl.run('show', 'list', 'json')
    return result.stdout.read()


#    выполняет команду ovs-vsctl add-port `bridge `port`
#   добавляет указанный порт в указанный мост с указанным тегом vlan
@app.route("/ovs-vsctl/add-port")
def route_ovs_vsctl_add_port():
    vsctl = VSCtl('tcp', '127.0.0.1', 6640)
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
    vsctl = VSCtl('tcp', '127.0.0.1', 6640)
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
    vsctl = VSCtl('tcp', '127.0.0.1', 6640)
    result = vsctl.run('add-br '+ bridge, 'list', 'json')
    return "bridge "+bridge+" has been added"

#    выполняет команду ovs-vsctl del-br `bridge`
#   удаляет указанный мост
@app.route("/ovs-vsctl/del-bridge")
def route_ovs_vsctl_del_bridge():
    bridge = request.args.get('bridge')
    if(bridge == None):
        return "specify bridge"
    vsctl = VSCtl('tcp', '127.0.0.1', 6640)
    result = vsctl.run('del-br '+ bridge, 'list', 'json')
    return "bridge "+bridge+" has been deleted"

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)