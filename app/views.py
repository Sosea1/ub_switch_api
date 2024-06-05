import pathlib
import subprocess
from app import webapi
import re
import json
from flask import Response, jsonify, render_template, request, redirect, url_for, flash, make_response, session
# from .models import User, Post, Category, Feedback, db
# from .forms import ContactForm, LoginForm
from .utils import get_all_ports, get_ovs_bridges, makeRequest, parse_to_json, nft_to_normal_json, execute_bash_script, execute_bash_command
from app import vsctl, cur
import os.path
from .dataclasses.dataclasses import ACL, ARP, ACLBinding, ACLRules, ARPTable, DHCPServer, PortDHCP
import hashlib
try:
    import yaml
except Exception as exc:
    print("Отсутствует модуль yaml: " + str(exc))


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
@webapi.route("/dhcp-snooping/enable", methods = ['POST'])
def route_nft_dhcp_snooping_enable():
    interface = request.args.get('int')
    path = "/root/dhcp_snooping/dhcp_snooping_" + interface + ".c"
    if os.path.isfile(path) == False:
        lines = None
        with open("/root/dhcp_snooping/dhcp_snooping_ip.c", 'r') as f:
            lines = f.readlines()
        with open(path, 'w') as f:
            for line in lines:
                new_line = line
                f.write(new_line)
    
    o_path = "/root/dhcp_snooping/dhcp_snooping_" + interface + ".o"
    command = "clang -O2 -g -Wall -target bpf -c {} -o {}".format(path, o_path)        
    command = "ip link set dev {} xdp object {} section xdp_udp_drop".format(interface, o_path)
    execute_bash_command(command)
    
    return "DHCP Snooping enabled"

#  Выключение DHCP Snooping 
@webapi.route("/dhcp-snooping/disable", methods = ['POST'])
def route_nft_dhcp_snooping_disable():
    interface = request.args.get('int')
    command = "ip link set {} xdpgeneric off".format(interface)
    execute_bash_command(command)
    
    return "DHCP Snooping disabled"


@webapi.route("/dhcp-snooping/add", methods = ['POST'])
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
    return "address added"


@webapi.route("/dhcp-snooping/remove", methods = ['POST'])
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
    
    o_path = "/root/dhcp_snooping/dhcp_snooping_" + interface + ".o"
    command = "clang -O2 -g -Wall -target bpf -c {} -o {}".format(path, o_path)
    execute_bash_command(command)
    
    return "address removed"

@webapi.route("/dhcp-snooping/view", methods = ['GET'])
def dhcp_snooping_view():
    excluded_ports = ['lo', 'ovs-system']
    ports = []
    devs = pathlib.Path("/sys/class/net/")
    for dir in devs.iterdir():
        if dir.name not in excluded_ports:
            print(dir.name)
            path = "/root/dhcp_snooping/dhcp_snooping_" + dir.name + ".c"
            dhcp_snooping = False
            if os.path.isfile(path):
                dhcp_snooping = True
            port = PortDHCP(port=dir.name, dhcp_snooping=dhcp_snooping)
            ports.append(port)
    
    return ports

@webapi.route("/dhcp-servers/view/<interface>", methods = ['GET'])
def dhcp_servers_view(interface):
    excluded_ports = ['lo', 'ovs-system']
    ports = []
    devs = pathlib.Path("/sys/class/net/")
    for dir in devs.iterdir():
        if dir.name not in excluded_ports:
            if dir.name != interface:
                continue
            path = "/root/dhcp_snooping/dhcp_snooping_" + dir.name + ".c"
            if os.path.isfile(path):
                ips = []
                with open(path, 'r') as f:
                    lines = f.readlines()
                for line in lines:
                    if "dhcp_server_ip[]" in line:
                        index = line.index("{")
                        index2 = line.index("}")
                        ips = line[index+1:index2].split(',')
                        if(ips[0] == ''):
                            ips = []
                for ip in ips:
                    ip = ip.replace('0x','')
                    n = 2
                    address = [ip[i:i+n] for i in range(0, len(ip), n)]
                    ip_address = ''
                    for add in address:
                        int_number = int(add, 16)
                        ip_address += str(int_number) + '.'
                    ip_address = ip_address[:-1]
                    port = DHCPServer(address=ip_address)
                    ports.append(port)
    
    return ports

#--------------DAI--------------------
@webapi.route("/arp/limit", methods = ['POST'])
def route_arp_limit():
    interface = request.args.get('int')
    if interface is None:
        return "specify interface"
    limit = ""
    limit_number = request.args.get('limit')
    if limit_number:
        limit = "limit rate {}/minute".format(limit_number)
    else:
        return "specify limit rate"
    json_ruleset = subprocess.run(["nft", "-j", "list", "ruleset"], capture_output=True, text=True)
    if json_ruleset.returncode != 0:
        return "The command failed with return code:\n"+json_ruleset.returncode
    json_ruleset = json.loads(json_ruleset.stdout)
    nftables = nft_to_normal_json(json_ruleset)
    if "table-ARP" not in nftables["data"]:
        script = []
        script.append("nft add table arp ARP")
        script.append("nft add chain arp ARP input { type filter hook input priority 0 \; policy accept \;}")
        script.append("nft add rule arp ARP input arp operation request iif {} {} counter accept".format(interface, limit))
        script.append("nft add rule arp ARP input arp operation reply iif {} {} counter accept".format(interface, limit))
        execute_bash_script(script)
    #print(json.dumps(json_ruleset, indent=4))
    return "DAI enabled for interface {}".format(interface)

@webapi.route("/arp/entry", methods = ['POST'])
def route_arp_entry():
    ip = request.args.get('ip')
    if ip is None:
        return "specify ip address"
    mac = request.args.get('mac')
    if mac is None:
        return "specify mac address"

    command = "arp -s {} {}".format(ip, mac)
    execute_bash_command(command)
    return "static for ip address = {} and mac address = {} entry added".format(ip, mac)



#--------------PORT SECURITY--------------------
@webapi.route("/port-security/create")
def route_port_security_create():
    json_ruleset = subprocess.run(["nft", "-j", "list", "ruleset"], capture_output=True, text=True)
    if json_ruleset.returncode != 0:
        return "The command failed with return code:\n"+json_ruleset.returncode
    json_ruleset = json.loads(json_ruleset.stdout)
    nftables = nft_to_normal_json(json_ruleset)
    script = []
    if "table-port_security" not in nftables["data"]:
        script.append("nft add table ip port_security")
        script.append("nft add chain ip port_security input { type filter hook input priority 0 \; }")
        script.append("nft add chain ip port_security forward { type filter hook forward priority 0 \; }")
        execute_bash_script(script)
    return "PORT SECURITY enabled"


@webapi.route("/port-security/add-static", methods = ['POST'])
def route_port_security_add_static():
    data = request.get_json()
    json_ruleset = subprocess.run(["nft", "-j", "list", "ruleset"], capture_output=True, text=True)
    if json_ruleset.returncode != 0:
        return "The command failed with return code:\n"+json_ruleset.returncode
    json_ruleset = json.loads(json_ruleset.stdout)
    nftables = nft_to_normal_json(json_ruleset)
    if "table-port_security" not in nftables["data"]:
        route_port_security_create()
    interface = data['interface']
    try:
        mac_address = data['mac_address']
    except:
        mac_address = None
    if interface == None:
        return jsonify("You must specify the interface")
    
    number_rules = 0
    try:
        number_rules = nftables["data"]["table-port_security"]["chain-input"]["count-rule"]
    except: 
        pass
    
    if number_rules >= 1:
        for i in range (0, number_rules):
            rule = "rule-"+str(number_rules-i)
            _interface = nftables["data"]["table-port_security"]["chain-input"][rule]["expr"][0]["match"]["right"]
            if _interface == interface:
                handle = nftables["data"]["table-port_security"]["chain-input"][rule]["handle"]
                command = "nft delete rule ip port_security input handle {}".format(handle)
                execute_bash_command(command)
                break
    
    if mac_address:
        command = "nft add rule ip port_security input iif {} ether saddr {} accept".format(interface, mac_address)
        execute_bash_command(command)
        command = "nft add rule ip port_security input iif {} drop".format(interface)
        execute_bash_command(command)
        return jsonify("Rule added for interface {} with MAC {}".format(interface, mac_address))
    
    else:
        command = "nft add rule ip port_security input iif {} drop".format(interface)
        execute_bash_command(command)
        return jsonify("Port Security enabled for interface {}".format(interface))
    
    



@webapi.route("/port-security/del-static", methods = ['DELETE'])
def route_port_security_del_static():
    data = request.get_json()
    json_ruleset = subprocess.run(["nft", "-j", "list", "ruleset"], capture_output=True, text=True)
    if json_ruleset.returncode != 0:
        return "The command failed with return code:\n"+json_ruleset.returncode
    json_ruleset = json.loads(json_ruleset.stdout)
    nftables = nft_to_normal_json(json_ruleset)
    if "table-port_security" not in nftables["data"]:
        route_port_security_create()
    interface = data['interface']
    try:
        mac_address = data['mac_address']
    except:
        mac_address = None
    if interface == None:
        return "You must specify the interface"
    
    number_rules = 0
    try:
        number_rules = nftables["data"]["table-port_security"]["chain-input"]["count-rule"]
    except: 
        pass

    if number_rules >= 1:
        for i in range (0, number_rules):
            rule = "rule-"+str(number_rules-i)
            _interface = nftables["data"]["table-port_security"]["chain-input"][rule]["expr"][0]["match"]["right"]
            if _interface == interface:
                handle = nftables["data"]["table-port_security"]["chain-input"][rule]["handle"]
                command = "nft delete rule ip port_security input handle {}".format(handle)
                execute_bash_command(command)
                break
    
    if mac_address:
        for i in range(1,number_rules):
            rule = "rule-"+str(i)
            _interface = nftables["data"]["table-port_security"]["chain-input"][rule]["expr"][0]["match"]["right"]
            if _interface != interface:
                continue
            _mac = nftables["data"]["table-port_security"]["chain-input"][rule]["expr"][1]["match"]["right"]
            if _mac != mac_address:
                continue
            handle = nftables["data"]["table-port_security"]["chain-input"][rule]["handle"]
            command = "nft delete rule ip port_security input handle {}".format(handle)
            execute_bash_command(command)
        return jsonify("Rule deleted for interface {} with MAC {}".format(interface, mac_address))
    
    else:
        command = "nft add rule ip port_security input iif {} accept".format(interface)
        execute_bash_command(command)
        return jsonify("Port Security disabled for interface {}".format(interface))



@webapi.route("/port-security/view", methods = ['GET'])
def route_port_security_view():
    json_ruleset = subprocess.run(["nft", "-j", "list", "ruleset"], capture_output=True, text=True)
    if json_ruleset.returncode != 0:
        return "The command failed with return code:\n"+json_ruleset.returncode
    json_ruleset = json.loads(json_ruleset.stdout)
    nftables = nft_to_normal_json(json_ruleset)
    if "table-port_security" not in nftables["data"]:
        route_port_security_create()
    
    ports = get_all_ports(("port_security", None))
    
    return ports
    
    


@webapi.route("/dos/sysctl/get",methods=['GET'])
def dos_sysctl_get():
    path = "/etc/sysctl.conf"
    if os.path.isfile(path):
        res={}
        with open(path, 'r') as f:
            for line in f:
                if not line.startswith('#'):
                    res.update({line.split('=')[0]: line.split('=')[1].strip()})
            return res
            
    else: return 'error'

@webapi.route("/dos/sysctl/change",methods=['POST'])
def dos_sysctl_change(): 
    path = "/etc/sysctl.conf"
    if os.path.isfile(path):
        with open(path, 'r') as f:
            in_file = f.readlines()

        settings_dict = {line.split('=')[0]: line.split('=')[1].strip() for line in in_file if '=' in line}
        data = request.get_json()
        
        for key, value in data.items():
            res=''
            val=''
            if str(key) in ['net.ipv4.conf.rp_filter', 'net.ipv4.conf.accept_redirects' , 'net.ipv4.conf.secure_redirects']:
                for in_key, in_value in value.items():
                    if str(in_key)=='interface':
                        tmp=str(key)
                        tmp = str(tmp).split('.')
                        tmp.insert(3, in_value)
                        res='.'.join(tmp)+res

                    if str(in_key)=='value':
                        val=in_value

                    if len(res)>0 and len(val)>0: settings_dict.update({res:val})
                
            elif str(key) in ['net.ipv4.icmp_echo_ignore_broadcasts', 'net.ipv4.icmp_ignore_bogus_error_responses', 'net.ipv4.icmp_echo_ignore_all', 'net.ipv4.tcp_syncookies', 'net.ipv4.tcp_max_syn_backlog', 'net.ipv4.tcp_synack_retries', 'net.ipv4.tcp_rfc1337', 'net.core.netdev_max_backlog', 'net.ipv4.tcp_keepalive_probes', 'net.ipv4.tcp_keepalive_intvl', 'net.ipv4.tcp_keepalive_time']:
                    for in_key, in_value in value.items():
                        if str(in_key)=='value':
                            settings_dict.update({key:in_value})
                
        with open(path, 'w') as f:                
            updated_settings = [f"{key}={value}\n" for key, value in settings_dict.items()]    
            f.writelines(updated_settings)

    return updated_settings
                

#------------------------ACL----------------------#
@webapi.route("/acl/view", methods = ['GET'])
def view_all_acls():
    with open("/etc/faucet/acls.yaml", "r") as file:
        data = yaml.safe_load(file)
    entries = []
    acls = list(data['acls'].keys())
    for acl in acls:
        rules = len(data['acls'][acl])
        entry = ACL(str(acl),rules)
        entries.append(entry)
    return entries      


@webapi.route("/acl/view-rules/<acl_name>", methods = ['GET'])
def view_rules_acl(acl_name):
    with open("/etc/faucet/acls.yaml", "r") as file:
        data = yaml.safe_load(file)
    entries = []
    number = 1
    acl = data['acls'][acl_name]
    for _ in acl:
        rule = _['rule']
        action = rule['actions']
        if 'allow' not in action:
            continue
        allow = int(action['allow'])
        ip_src = None
        ip_dst = None
        protocol = None
        p_src = None
        d_src = None
        if 'ipv4_src' in rule:
            ip_src = rule['ipv4_src']
        if 'ipv4_dst' in rule:
            ip_dst = rule['ipv4_dst']
        if 'nw_proto' in rule:
            temp = int(rule['nw_proto'])
            match temp:
                case 17:
                    protocol = "udp"
                case 6:
                    protocol = "tcp"
                case 1:
                    protocol = "icmp"
        if protocol is not None:
            if protocol == "tcp":
                if 'tcp_src' in rule:
                    p_src = str(rule['tcp_src'])
                if 'tcp_dst' in rule:
                    d_src = str(rule['tcp_dst'])
            elif protocol == "udp":
                if 'udp_src' in rule:
                    p_src = str(rule['udp_src'])
                if 'udp_dst' in rule:
                    d_src = str(rule['udp_dst'])
        entry = ACLRules(rule_id=number, allow=allow, s_ip=ip_src, d_ip=ip_dst,
                         protocol=protocol, p_src=p_src, d_src=d_src)
        entries.append(entry)
        number += 1
        
    return entries

@webapi.route("/acl/binding/view", methods = ['GET'])
def view_binding():
    bridges = get_ovs_bridges()
    for bridge in bridges:
        data = subprocess.run(["ovs-ofctl", "dump-ports-desc", bridge,], capture_output=True, text=True)
        if data.returncode != 0:
            return "The command failed with return code:\n"+data.returncode
        data = data.stdout
        regex = re.compile(r"\w+\(\w+\)")
        result = regex.findall(data)
        with open("/etc/faucet/faucet.yaml", "r") as file:
            data2 = yaml.safe_load(file)
        entries = []
        interfaces = list(data2['dps']['sw1']['interfaces'].keys())
        for port in result:
            temp = port.replace(')','').split('(')
            try:
                ofctl = int(temp[0])
            except:
                continue
            vsctl = temp[1]
            if ofctl in interfaces:
                acls = data2['dps']['sw1']['interfaces'][ofctl]
                if 'acls_in' in acls:
                    name = acls['acls_in'][0]
                    entry = ACLBinding(acl_name=name, port=vsctl,
                                       direction='Ingress')
                    entries.append(entry)
    return entries

@webapi.route("/acl/create-acl", methods = ['POST'])
def create_acl():
    return 

@webapi.route("/acl/create-rule", methods = ['POST'])
def create_rule():
    return 

@webapi.route("/acl/binding/create", methods = ['POST'])
def create_binding():
    return   

#------------------------ARP---------------------------#
@webapi.route("/arp-table", methods = ['GET'])
def view_arp_table():
    entries = []
    data = subprocess.run("arp -n | jc --arp", shell=True, capture_output=True, text=True)
    data = data.stdout
    data = json.loads(data)
    for acl in data:
        if 'flags_mask' not in list(acl.keys()):
            continue
        if 'M' in acl['flags_mask']:
            ip = acl['address']
            mac = acl['hwaddress']
            entry = ARPTable(ip, mac)
            entries.append(entry)
    return entries     

@webapi.route("/arp", methods = ['GET'])
def arp_view():
    excluded_ports = ['lo', 'ovs-system']
    ports = []
    devs = pathlib.Path("/sys/class/net/")
    for dir in devs.iterdir():
        if dir.name not in excluded_ports:
            port = ARP(port=dir.name, arp=1 if dir.name == "enp0s8" else 0)
            ports.append(port)
    return ports


count = 0

#-----------------AUTHENTICATE--------------------------#
@webapi.route("/login", methods = ['GET'])
def login():
    username = request.args.get('username')
    password = request.args.get('password')
    # password = "secret" + password + "solt12"
    # hash_object = hashlib.sha256()
    # hash_object.update(password.encode())
    # hash_password = hash_object.hexdigest()
    # res = cur.execute("SELECT login FROM users WHERE login='?' AND password='?'",
    #                   (username, hash_password))
    
    # if (res.fetchone() is None):
    #     return "Пользователь не зарегистрирован"
    
    if username != 'admin' or password != 'Qwerty123':
        global count
        if count >= 5:
            return Response("Произведено слишком много попыток входа", status=429,mimetype='application/json' )
        count += 1
        return Response("Неверно введен логин или пароль", status=401,mimetype='application/json' )
    else:
        return "Вход произошел успешно" 
    

    

@webapi.route("/register", methods = ['POST'])
def register():
    data = request.get_json()
    username = data['username']
    password = data['password']
    password = "secret" + password + "solt12"
    hash_object = hashlib.sha256()
    # Convert the password to bytes and hash it
    hash_object.update(password.encode())
    # Get the hex digest of the hash
    hash_password = hash_object.hexdigest()
    res = cur.execute("INSERT INTO users (login, password) VALUES (?,?)",username,hash_password)
    return json.dumps("Пользователь успешно зарегистрирован" )


#-----------------DOS---------------------------------------------------------------
#-----1------
#net.ipv4.conf.all.rp_filter=1
#sysctl -w net.ipv4.conf.eth0.rp_filter=1
#----Параметр который включает фильтр обратного пути, проще говоря активируется защита от подмены адресов (спуфинга).
#---0-выкл, 1-вкл, 2-вкл(свободный режим проверки).
#
#-----2------
# sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
#
#----Отключаем ответ на ICMP ECHO запросы, переданные широковещательными пакетами
#---0-выкл, 1-вкл
#
#-----3------
# sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
#
#----Игнорируем ошибочные ICMP запросы.
#---0-выкл, 1-вкл
#
#-----4------
#sysctl -w net.ipv4.icmp_echo_ignore_all=1
#
#----Отключаем ответ на ICMP запросы (сервер не будет пинговаться).
#---0-выкл, 1-вкл
#
#-----5------
#sysctl -w net.ipv4.tcp_syncookies=0
#
#----По умолчанию данный параметр обычно включен. Если количество SYN пакетов забивает всю очередь, включается механизм Syn cookies.
#---0-выкл, 1-вкл
#
#-----6------
#sysctl -w net.ipv4.tcp_max_syn_backlog=4096
#
#----Параметр, который определяет максимальное число запоминаемых запросов на соединение, для которых не было получено подтверждения от подключающегося клиента (полуоткрытых соединений).
#---от 0 до много
#
#-----7------
#sysctl -w net.ipv4.tcp_synack_retries=1
#
#----Время удержания «полуоткрытых» соединений.
#---по умолчанию 5
#
#-----8------
# sysctl -w net.ipv4.tcp_max_orphans=65536
#
#----Определяет максимальное число «осиротевших» TCP пакетов.
#---по умолчанию 262144
#
#-----9------
#sysctl -w net.ipv4.tcp_fin_timeout=10
#
#----Время ожидания приема FIN до полного закрытия сокета.
#---по умолчанию 60
#
#-----10------
#sysctl -w net.ipv4.tcp_keepalive_time=60
#
#----Проверять TCP-соединения, с помощью которой можно убедиться в том что на той стороне легальная машина, так как она сразу ответит..
#---по умолчанию 7200 (2 часа), лучше уменьшить это время
#
#-----11------
#sysctl -w net.ipv4.tcp_keepalive_intvl=15
#
#----Интервал подачи проб.
#---по умолчанию 75
#
#-----12------
#sysctrl -w net.ipv4.tcp_keepalive_probes=5
#
#----Количество проверок перед закрытием соединения..
#---по цмолчанию 9 попыток
#
#-----13------
#sysctl -w net.core.netdev_max_backlog=1000
#
#----Параметр определяет максимальное количество пакетов в очереди на обработку, если интерфейс получает пакеты быстрее, чем ядро может их обработать..
#---по умолчанию 1000
#
#-----14------
#sysctl -w net.ipv4.tcp_rfc1337=1
#
#----С помощью этой опции мы можем защитить себя от TIME_WAIT атак.
#---0-выкл, 1-вкл
