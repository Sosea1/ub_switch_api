#!/bin/false
# pip3 install ovs --break-system-packages
# ovs-vsctl set-manager ptcp:127.0.0.1:6640

import collections
import json
import re
from typing import Union
import ovs
import ovs.jsonrpc
import os
import subprocess
from copy import deepcopy


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
            
    return nftables
    
def execute_bash_script(script: Union[list, str]):
    if isinstance(script, list):
        for command in script:
            subprocess.run(command, shell=True, executable="/bin/bash")
    
    else:
        return "str type not supported"
                
def execute_bash_command(command: str):
    subprocess.run(command, shell=True, executable="/bin/bash")
    

        