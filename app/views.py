import subprocess
from app import webapi
import json
from flask import render_template, request, redirect, url_for, flash, make_response, session
# from .models import User, Post, Category, Feedback, db
# from .forms import ContactForm, LoginForm
from .utils import makeRequest, parse_to_json, nft_to_normal_json, execute_bash_script, execute_bash_command
try:
    from ovs_vsctl import VSCtl, parser
except Exception as exc:
    print("Отсутствует модуль ovs_vsctl: " + str(exc))
from app import vsctl
import os.path


@webapi.route("/")
def hello_world():
    return "<p>Hello, World!</p>"


#----------simple_interface-------------#
#    Простой интерфейс управления и отладки
#    /simple
#    simple_interface.py


#----------ovs-------------#
#    выводит схему базы данных OpenVSwitch
@webapi.route("/ovs/get-schema", methods = ['GET'])
def route_ovs_get_schema():
    return makeRequest('tcp:127.0.0.1:6640', 'get_schema', ['Open_vSwitch']).result
    


#----------ovs-vsctl-------------#
#    выполняет команду ovs-vsctl show
#    выводит схему OpenVSwitch
@webapi.route("/ovs-vsctl/show", methods = ['GET'])
def route_ovs_vsctl_show():
    result = vsctl.run('show', 'list', 'json')
    result = result.stdout.read().strip()
    return parse_to_json(result)


#    выполняет команду ovs-vsctl add-port `bridge `port`
#   добавляет указанный порт в указанный мост с указанным тегом vlan
@webapi.route("/ovs-vsctl/add-port")
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
@webapi.route("/ovs-vsctl/del-port")
def route_ovs_vsctl_del_port():
    bridge = request.args.get('bridge')
    port = request.args.get('port')
    if(bridge == None or port == None):
        return "specify bridge and port"
    result = vsctl.run('del-port '+ bridge+' '+port, 'list', 'json')
    return "port "+port+" deleted from "+bridge



#    выполняет команду ovs-vsctl add-br `bridge`
#   добавляет указанный мост
@webapi.route("/ovs-vsctl/add-bridge")
def route_ovs_vsctl_add_bridge():
    bridge = request.args.get('bridge')      #берет из строки запроса аргумент `bridge` - название моста
    if(bridge == None):
        return "specify bridge"
    result = vsctl.run('add-br '+ bridge, 'list', 'json')
    return "bridge "+bridge+" has been added"

#    выполняет команду ovs-vsctl del-br `bridge`
#   удаляет указанный мост
@webapi.route("/ovs-vsctl/del-bridge")
def route_ovs_vsctl_del_bridge():
    bridge = request.args.get('bridge')
    if(bridge == None):
        return "specify bridge"
    result = vsctl.run('del-br '+ bridge, 'list', 'json')
    return "bridge "+bridge+" has been deleted"

#    Пример запроса для выполнения команды linux
#   Запрашиваем версию nftables 
@webapi.route("/nft/get-version")
def route_nft_get_version():
    result = subprocess.run(["nft", "-v"], capture_output=True, text=True)
    if result.returncode != 0:
        return "The command failed with return code:\n"+result.returncode
    return result.stdout


#   Включение фильтрации пакетов для интерфейса
#   Для использования необходимо так же создавать таблицу и семейство для фильтрации
@webapi.route("/nft/mac-filtering", methods=['POST'])
def route_nft_mac_filtering():
    interface = request.args.get('interface')
    mac = request.args.get('mac')
    if not interface or not mac:
        return "interface and mac are required"
    result = subprocess.run([
        "nft", "add rule filter input iif {} ether saddr != {} drop".format(interface, mac)],
        capture_output=True, text=True)
    if result.returncode != 0:
        return "The command failed with return code:\n"+str(result.returncode)
    return result.stdout


#--------------DHCP SNOOPING--------------------

# Вывод списка правил nft в json формате
@webapi.route("/nft-ruleset")
def route_nft_ruleset():
    json_ruleset = subprocess.run(["nft", "-j", "list", "ruleset"], capture_output=True, text=True)
    if json_ruleset.returncode != 0:
        return "The command failed with return code:\n"+json_ruleset.returncode
    json_ruleset = json.loads(json_ruleset.stdout)
    nftables = nft_to_normal_json(json_ruleset)
    return nftables

#  Включение DHCP Snooping 
@webapi.route("/dhcp-snooping/enable")
def route_nft_dhcp_snooping_enable():
    interfaces = request.args.getlist('int')
    path_to_script = "/root/dhcp_snooping/dhcp_snooping.o"  # может быть другой, подготовить нужно самим
    for interface in interfaces:
        command = "ip link set dev {} xdp object {} section xdp_udp_drop".format(interface, path_to_script)
        execute_bash_command(command)
    
    return "DHCP Snooping enabled for all given interfaces"

#  Выключение DHCP Snooping 
@webapi.route("/dhcp-snooping/disable")
def route_nft_dhcp_snooping_disable():
    interfaces = request.args.getlist('int')
    for interface in interfaces:
        command = "ip link set {} xdpgeneric off".format(interface)
        execute_bash_command(command)
    
    return "DHCP Snooping disabled for all given interfaces"


@webapi.route("/dhcp-snooping/add")
def route_nft_dhcp_snooping_add():
    interface = request.args.get('int')
    address = request.args.get('address')
    if interface is None:
        return "specify interface"
    if address is None:
        return "specify address"
    address = list(address.split('.'))
    address = list(map(int, address))
    address = list(map(hex, address))
    ip_address = '0x'
    for add in address:
        hex_ = add[2:]
        if (len(hex_) == 1):
            hex_ = '0' + hex_
        ip_address += hex_
    path = "/root/dhcp_snooping/dhcp_snooping_" + interface + ".c"
    if os.path.isfile(path):
        lines = None
        with open(path, 'r') as f:
            lines = f.readlines()
        with open(path, 'w') as f:
            for line in lines:
                new_line = line
                if "dhcp_server_ip[]" in line:
                    index = line.index("{")
                    index2 = line.index("}")
                    ips = line[index+1:index2].split(',')
                    if(ips[0] == ''):
                        ips = []
                    if ip_address not in ips:
                        ips.append(ip_address)
                        
                    new_line = "uint32_t dhcp_server_ip[] = {"
                    for i in range(len(ips)):
                        if i == len(ips) - 1:
                            new_line += ips[i] + "};\n"
                        else:
                            new_line += ips[i] + ","
                f.write(new_line)
    else:
        lines = None
        with open("/root/dhcp_snooping/dhcp_snooping_ip.c", 'r') as f:
            lines = f.readlines()
        with open(path, 'w') as f:
            for line in lines:
                new_line = line
                if "dhcp_server_ip[]" in line:
                    index = line.index("{")
                    index2 = line.index("}")
                    ips = line[index+1:index2].split(',')
                    if(ips[0] == ''):
                        ips = []
                    if ip_address not in ips:
                        ips.append(ip_address)
                    new_line = "uint32_t dhcp_server_ip[] = {"
                    for i in range(len(ips)):
                        if i == len(ips) - 1:
                            new_line += ips[i] + "};\n"
                        else:
                            new_line += ips[i] + ","
                f.write(new_line)
    o_path = "/root/dhcp_snooping/dhcp_snooping_" + interface + ".o"
    command = "clang -O2 -g -Wall -target bpf -c {} -o {}".format(path, o_path)
    execute_bash_command(command)
    command = "ip link set {} xdpgeneric off".format(interface)
    execute_bash_command(command)
    command = "ip link set dev {} xdp object {} section xdp_udp_drop".format(interface, o_path)
    execute_bash_command(command)
    return "address added"


@webapi.route("/dhcp-snooping/remove")
def route_nft_dhcp_snooping_remove():
    interface = request.args.get('int')
    address = request.args.get('address')
    if interface is None:
        return "specify interface"
    if address is None:
        return "specify address"
    address = list(address.split('.'))
    address = list(map(int, address))
    address = list(map(hex, address))
    ip_address = '0x'
    for add in address:
        hex_ = add[2:]
        if (len(hex_) == 1):
            hex_ = '0' + hex_
        ip_address += hex_
    path = "/root/dhcp_snooping/dhcp_snooping_" + interface + ".c"
    flag = False
    if os.path.isfile(path):
        lines = None
        with open(path, 'r') as f:
            lines = f.readlines()
        with open(path, 'w') as f:
            for line in lines:
                new_line = line
                if "dhcp_server_ip[]" in line:
                    index = line.index("{")
                    index2 = line.index("}")
                    ips = line[index+1:index2].split(',')
                    if(ips[0] == ''):
                        ips = []
                    try:
                        ips.remove(ip_address)
                    except:
                        return "Такого адреса нет"
                        
                    new_line = "uint32_t dhcp_server_ip[] = {"
                    if(len(ips) == 0):
                        flag = True
                        new_line += "};\n"
                    for i in range(len(ips)):
                        if i == len(ips) - 1:
                            new_line += ips[i] + "};\n"
                        else:
                            new_line += ips[i] + ","
                f.write(new_line)
    else:
        return "Такого адреса нет"
    
    command = "ip link set {} xdpgeneric off".format(interface)
    execute_bash_command(command)
    if flag == True: 
        o_path = "/root/dhcp_snooping/dhcp_snooping.o"
        command = "ip link set dev {} xdp object {} section xdp_udp_drop".format(interface, o_path)
        execute_bash_command(command)
        
    else:
        o_path = "/root/dhcp_snooping/dhcp_snooping_" + interface + ".o"
        command = "clang -O2 -g -Wall -target bpf -c {} -o {}".format(path, o_path)
        execute_bash_command(command)
        command = "ip link set dev {} xdp object {} section xdp_udp_drop".format(interface, o_path)
        execute_bash_command(command)
    
    return "address added"


#--------------PORT SECURITY--------------------
@webapi.route("/port-security/enable")
def route_port_security_enable():
    json_ruleset = subprocess.run(["nft", "-j", "list", "ruleset"], capture_output=True, text=True)
    if json_ruleset.returncode != 0:
        return "The command failed with return code:\n"+json_ruleset.returncode
    json_ruleset = json.loads(json_ruleset.stdout)
    nftables = nft_to_normal_json(json_ruleset)
    if "table-port_security" not in nftables["data"]:
        script = []
        script.append("nft add table ip port_security")
        script.append("nft add chain ip port_security input { type filter hook input priority 0 \; }")
        script.append("nft add chain ip port_security forward { type filter hook forward priority 0 \; }")
        execute_bash_script(script)
    #print(json.dumps(json_ruleset, indent=4))
    return "PORT SECURITY enabled"

@webapi.route("/port-security/disable")
def route_port_security_disable():
    json_ruleset = subprocess.run(["nft", "-j", "list", "ruleset"], capture_output=True, text=True)
    if json_ruleset.returncode != 0:
        return "The command failed with return code:\n"+json_ruleset.returncode
    json_ruleset = json.loads(json_ruleset.stdout)
    nftables = nft_to_normal_json(json_ruleset)
    if "table-port_security" not in nftables["data"]:
        script = []
        script.append("nft delete table ip port_security")
        execute_bash_script(script)
    #print(json.dumps(json_ruleset, indent=4))
    return "PORT SECURITY enabled"

@webapi.route("/port_security/static")
def route_port_security_static():
    json_ruleset = subprocess.run(["nft", "-j", "list", "ruleset"], capture_output=True, text=True)
    if json_ruleset.returncode != 0:
        return "The command failed with return code:\n"+json_ruleset.returncode
    json_ruleset = json.loads(json_ruleset.stdout)
    nftables = nft_to_normal_json(json_ruleset)
    if "table-port_security" not in nftables["data"]:
        return "PORT SECURITY not enabled. \n Use route '/port-security/enable' to enable PORT SECURITY"
    interface = request.args.get('interface')
    mac_address = request.args.get('mac_address')
    if interface == None:
        return "You must specify the interface"
        
    command = "nft add rule ip port_security input iif {} ether saddr != {} drop".format(interface, mac_address)
    execute_bash_command(command)
    
    return "Rule added"

@webapi.route("/port_security/sticky")
def route_port_security_sticky():
    json_ruleset = subprocess.run(["nft", "-j", "list", "ruleset"], capture_output=True, text=True)
    if json_ruleset.returncode != 0:
        return "The command failed with return code:\n"+json_ruleset.returncode
    json_ruleset = json.loads(json_ruleset.stdout)
    nftables = nft_to_normal_json(json_ruleset)
    if "table-port_security" not in nftables["data"]:
        return "PORT SECURITY not enabled. \n Use route '/port-security/enable' to enable PORT SECURITY"
    interface = request.args.get('interface')
    mac_address = request.args.get('mac_address')
    action = request.args.get('action')
    if interface == None:
        return "You must specify the interface"
        
    if action is None:      
        command = "nft add rule ip port_security input iif {} ether saddr != {} drop".format(interface, mac_address, action)
        execute_bash_command(command)
        
    else:      
        command = "nft add rule ip port_security input iif {} ether saddr {} {}".format(interface, mac_address, action)
        execute_bash_command(command)

    
    return "Rule added"

@webapi.route("/port_security/violation")
def route_nft_port_security_violation():
    interface = request.args.get('interface')
    action = request.args.get('action')

    # action == Protect or Restrict or Shutdown
    
    return "Не реализовано пока"