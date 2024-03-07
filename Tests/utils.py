#!/bin/false
# pip3 install ovs --break-system-packages
# ovs-vsctl set-manager ptcp:127.0.0.1:6640

import ovs
import ovs.jsonrpc
import os


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