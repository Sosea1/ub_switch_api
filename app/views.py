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
@webapi.route("/dhcp-snooping/ruleset")
def route_nft_dhcp_snooping_ruleset():
    json_ruleset = subprocess.run(["nft", "-j", "list", "ruleset"], capture_output=True, text=True)
    if json_ruleset.returncode != 0:
        return "The command failed with return code:\n"+json_ruleset.returncode
    json_ruleset = json.loads(json_ruleset.stdout)
    nftables = nft_to_normal_json(json_ruleset)
    return nftables

#  Включение DHCP Snooping 
@webapi.route("/dhcp-snooping/enable")
def route_nft_dhcp_snooping_enable():
    json_ruleset = subprocess.run(["nft", "-j", "list", "ruleset"], capture_output=True, text=True)
    if json_ruleset.returncode != 0:
        return "The command failed with return code:\n"+json_ruleset.returncode
    json_ruleset = json.loads(json_ruleset.stdout)
    nftables = nft_to_normal_json(json_ruleset)
    if "table-dhcp_snooping" not in nftables["data"]:
        script = []
        script.append("nft add table ip dhcp_snooping")
        script.append("nft add chain ip dhcp_snooping input { type filter hook input priority 0 \; }")
        script.append("nft add chain ip dhcp_snooping forward { type filter hook forward priority 0 \; }")
        script.append("nft add rule ip dhcp_snooping input ct state established,related accept")
        script.append("nft add rule ip dhcp_snooping input ct state invalid drop")
        script.append("nft add rule ip dhcp_snooping input udp dport 67 drop")
        script.append("nft add rule ip dhcp_snooping input udp dport 68 drop")
        execute_bash_script(script)
        
    elif "chain-input" not in nftables["data"]["table-dhcp_snooping"]:
        script = []
        script.append("nft add chain ip dhcp_snooping input { type filter hook input priority 0 \; }")
        script.append("nft add rule ip dhcp_snooping input ct state established,related accept")
        script.append("nft add rule ip dhcp_snooping input ct state invalid drop")
        script.append("nft add rule ip dhcp_snooping input udp dport 67 drop")
        script.append("nft add rule ip dhcp_snooping input udp dport 68 drop")
        execute_bash_script(script)
    
    elif "ct" not in nftables["data"]["table-dhcp_snooping"]["chain-input"]:
        script = []
        script.append("nft add rule ip dhcp_snooping input ct state established,related accept")
        script.append("nft add rule ip dhcp_snooping input ct state invalid drop")
        execute_bash_script(script)
        
    elif "protocol" not in nftables["data"]["table-dhcp_snooping"]["chain-input"]:
        script = []
        script.append("nft add rule ip dhcp_snooping input udp dport 67 drop")
        script.append("nft add rule ip dhcp_snooping input udp dport 68 drop")
        execute_bash_script(script)
    
    
    #print(json.dumps(json_ruleset, indent=4))
    return "DHCP Snooping enabled"

#  Выключение DHCP Snooping 
@webapi.route("/dhcp-snooping/disable")
def route_nft_dhcp_snooping_disable():
    json_ruleset = subprocess.run(["nft", "-j", "list", "ruleset"], capture_output=True, text=True)
    if json_ruleset.returncode != 0:
        return "The command failed with return code:\n"+json_ruleset.returncode
    json_ruleset = json.loads(json_ruleset.stdout)
    nftables = nft_to_normal_json(json_ruleset)
    
    if "table-dhcp_snooping" not in nftables["data"]:
        return "DHCP Snooping not enabled"
    else:
        command = "nft delete rule dhcp_snooping input handle {}".format()
        execute_bash_command(command)

    #print(json.dumps(json_ruleset, indent=4))
    return "DHCP Snooping enabled"


@webapi.route("/dhcp-snooping")
def route_nft_dhcp_snooping():
    json_ruleset = subprocess.run(["nft", "-j", "list", "ruleset"], capture_output=True, text=True)
    if json_ruleset.returncode != 0:
        return "The command failed with return code:\n"+json_ruleset.returncode
    json_ruleset = json.loads(json_ruleset.stdout)
    nftables = nft_to_normal_json(json_ruleset)
    if "table-dhcp_snooping" not in nftables["data"]:
        return "DHCP Snooping not enabled. \n Use route '/dhcp-snooping/enable' to enable DHCP Snooping"
    interface = request.args.get('interface')
    trust = request.args.get('trust')
    server_address = request.args.get('dhcp_ip')
    if interface == None:
        return "You must specify the interface"
    
    if server_address is None:
        
        if trust.lower() == "yes":
            action = "accept"
            
        elif trust.lower() == "no":
            action = "drop"
            
        else:
            return "trust can be either 'yes' or 'no'"
        
                
        table_name = "table-dhcp_snooping"
        chain_name = "chain-input"
            
        number = sum([1 for key in nftables["data"][table_name][chain_name].keys()
                            if key.startswith("rule")])
        rule_number = "rule-"+str(number)
        handle = nftables["data"][table_name][chain_name][rule_number]["handle"]
        command = "nft delete rule dhcp_snooping input handle {}".format(handle)
        execute_bash_command(command)
        rule_number = "rule-"+str(number-1)
        handle = nftables["data"][table_name][chain_name][rule_number]["handle"]
        command = "nft delete rule dhcp_snooping input handle {}".format(handle)
        execute_bash_command(command)
        
        command = "nft add rule ip dhcp_snooping input iif {} udp dport 67 {}".format(interface, action)
        execute_bash_command(command)
        command = "nft add rule ip dhcp_snooping input iif {} udp dport 68 {}".format(interface, action)
        execute_bash_command(command)
        script = []
        script.append("nft add rule ip dhcp_snooping input udp dport 67 drop")
        script.append("nft add rule ip dhcp_snooping input udp dport 68 drop")
        execute_bash_script(script)
        
    return "Rule added"



#--------------PORT SECURITY--------------------
@webapi.route("/port-security/enable")
def route_nft_port_security_enable():
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


@webapi.route("/port_security")
def route_nft_port_security():
    json_ruleset = subprocess.run(["nft", "-j", "list", "ruleset"], capture_output=True, text=True)
    if json_ruleset.returncode != 0:
        return "The command failed with return code:\n"+json_ruleset.returncode
    json_ruleset = json.loads(json_ruleset.stdout)
    nftables = nft_to_normal_json(json_ruleset)
    if "table-port_security" not in nftables["data"]:
        return "PORT SECURITY not enabled. \n Use route '/port-security/enable' to enable PORT SECURITY"
    interface = request.args.get('interface')
    print(interface)
    mac_address = request.args.get('mac_address')
    print(mac_address)
    action = request.args.get('action')
    print(action)
    if interface == None:
        return "You must specify the interface"
        
    if action is None:      
        command = "nft add rule ip port_security input iif {} ether saddr != {} drop".format(interface, mac_address, action)
        execute_bash_command(command)
        
    else:      
        command = "nft add rule ip port_security input iif {} ether saddr {} {}".format(interface, mac_address, action)
        execute_bash_command(command)

    
    return "Rule added"