#!/bin/false
# pip3 install ovs --break-system-packages
# ovs-vsctl set-manager ptcp:127.0.0.1:6640

import collections
import json
import pathlib
import re
try:
    from turtle import Turtle
except:
    Turtle = NotImplemented
from typing import Union
import ovs
import ovs.jsonrpc
import os
import subprocess
from copy import deepcopy
from app import vsctl

from .dataclasses.dataclasses import PSPorts


def tabulateError(err):
    log = ''
    for line in str(err).split('\n'):
        log += f'\n\t{line}'

    return log


def makeTest(func):
    try:
        func()
        exit(0)
    except Exception as exc:
        print(f'В ходе выполнения теста произошла ошибка: {tabulateError(exc)}')
        exit(-1)


def makeRequest(address: str, method: str, params: list = []):
    # Формируем json-rpc запрос для отправки на сервер ovs 
    msg = ovs.jsonrpc.Message.create_request(method, params)
    err = msg.is_valid()
    if err:
        raise RuntimeError(f'Не удалось сформировать JSON-RPC запрос: {err}')

    # Открытие сокета к адресу (address='ptcp:127.0.0.1:6640')
    err, stream = ovs.stream.Stream.open_block(ovs.stream.Stream.open(address))
    if err:
        raise RuntimeError(f'Нет доступа к серверу OVS (ovs-vsctl set-manager {address}): {tabulateError(os.strerror(err))}')

    # Создаём соединение
    rpc = ovs.jsonrpc.Connection(stream)
    # Отправка команды с приёмом ответа
    err, data = rpc.transact_block(msg)
    if err:
        raise RuntimeError(f'Не удалось совершить запрос к серверу OVS: {tabulateError(err)}')

    if data.error:
        raise RuntimeError(f'Ошибка выполнения запроса OVS: {tabulateError(data.error)}')

    return data

def parse_to_json(result:str):
        
        result_tmp = result.splitlines()
        dliya_dublicates = []

        for i in range(len(result_tmp)):
            result_tmp[i] = result_tmp[i].lstrip()
            result_tmp[i] = re.sub('([^\s:"]+(?=(?:[^"]+"[^"]+")*[^"]*$))', '"\g<1>"', result_tmp[i])
            if (': ' not in result_tmp[i]):
                result_tmp[i] = re.sub(' ', ':', result_tmp[i])
            if (':' not in result_tmp[i]):
                result_tmp[i] = result_tmp[i] + ":null"
            if i != len(result_tmp) - 1:
                result_tmp[i] = result_tmp[i] + ","
            dliya_dublicates.append(result_tmp[i].split(":")[0]) 
        dublicates = [item for item, count in collections.Counter(dliya_dublicates).items() if count > 1]
        for item in dublicates:
            indexes = [i for i,val in enumerate(result_tmp) if val.startswith(item)]
            count = 1
            for index in indexes:
                tmp = result_tmp[index].split(":")
                result_tmp[index] = tmp[0].rstrip('"') + str(count)+ '":' +tmp[1]
                count+=1
        result = '\n'.join(char for char in result_tmp)
        result = "{} {}".format('{', result)
        result = "{} {}".format(result, '}')
        result = json.loads(result, strict=False, object_pairs_hook=collections.OrderedDict)
        result = json.dumps(result, indent=4)
        return result
    
def nft_to_normal_json(json_ruleset):
    ruleset = deepcopy(json_ruleset)
    nftables = ruleset["nftables"][0]
    nftables.update({"data":{}})
    for value in json_ruleset["nftables"]:
        if "table" in value:
            name = "table-"+value["table"]["name"]
            nftables["data"].update({name : value["table"]})
        if "chain" in value:
            table_name = "table-"+value["chain"]["table"]
            chain_name = "chain-"+value["chain"]["name"]
            nftables["data"][table_name].update({chain_name : value["chain"]})
        if "rule" in value:
            table_name = "table-"+value["rule"]["table"]
            chain_name = "chain-"+value["rule"]["chain"]
            
            number = sum([1 for key in nftables["data"][table_name][chain_name].keys()
                            if key.startswith("rule")])
            number += 1
            rule_name = "rule-"+str(number)
            nftables["data"][table_name][chain_name].update({rule_name : value["rule"]})
            nftables["data"][table_name][chain_name].update({"count-rule" : number})
            
    return nftables
    
def execute_bash_script(script: Union[list, str]):
    if isinstance(script, list):
        for command in script:
            subprocess.run(command, shell=True, executable="/bin/bash")
    
    else:
        return "str type not supported"
                
def execute_bash_command(command: str):
    subprocess.run(command, shell=True, executable="/bin/bash")

def search_key_in_dict(haystack, needle, path=None) -> list:
    if path is None:
        path = []
    if isinstance(haystack, dict):
        if needle in haystack:
            path.append(needle)
            return path
        for k, v in haystack.items():
            result = search_key_in_dict(v, needle, path + [k])
            if result is not None:
                return result
    elif isinstance(haystack, list):
        for idx, v in enumerate(haystack):
            result = search_key_in_dict(v, needle, path + [idx])
            if result is not None:              
                return result


def get_all_ports(args: Turtle) -> list:
    excluded_ports = ['lo', 'ovs-system']
    ports = []
    devs = pathlib.Path("/sys/class/net/")
    for dir in devs.iterdir():
        if dir.name not in excluded_ports:
            port = None
            key, value = args
            match key:
                case "port_security":
                    json_ruleset = subprocess.run(["nft", "-j", "list", "ruleset"], capture_output=True, text=True)
                    if json_ruleset.returncode != 0:
                        return "The command failed with return code:\n"+json_ruleset.returncode
                    json_ruleset = json.loads(json_ruleset.stdout)
                    nftables = nft_to_normal_json(json_ruleset)
                    
                    number_rules = 0
                    try:
                        number_rules = nftables["data"]["table-port_security"]["chain-input"]["count-rule"]
                    except: 
                        pass
                    
                    mac_count = 0
                    status = False
                    for i in range(1,number_rules+1):
                        rule = "rule-"+str(i)
                        _interface = nftables["data"]["table-port_security"]["chain-input"][rule]["expr"][0]["match"]["right"]
                        if _interface == dir.name:
                            accept = nftables["data"]["table-port_security"]["chain-input"][rule]["expr"]
                            if len(accept) <= 2:
                                _ = nftables["data"]["table-port_security"]["chain-input"][rule]["expr"][1]
                                if "accept" in _:
                                    status = False
                                else:
                                    status = True
                                continue
                            mac_count+=1
                            status = True
                    port = PSPorts(dir.name,
                                   mac_count,
                                   mac_count,
                                   False,
                                   "Delete on Timeout",
                                   status)
                case _:
                    port = dir.name
            
            ports.append(port)
    
    return ports


def get_ovs_bridges():
    result = vsctl.run('list-br')
    result = result.stdout.read().strip().split('\n')
    return result