from app import webapi
from flask import request, send_from_directory, make_response
from enum import Enum
from . import switch
import traceback

class Flags(Enum):
    SWC_NOT_INITIALIZED = 1,
    BUG = 2

def _parse_flags(flags):
    if not isinstance(flags, set):
        if isinstance(flags, list):
            flags = set(flags)
        elif not flags:
            flags = set()
        else:
            raise RuntimeError("Поле flags должно быть списком или сетом из флагов (simple_interface.Flags), получено " + type(flags))

    # Сообщаем о том, что ядро не инициализировано
    if not isinstance(switch.SWC, switch.SwitchCore) or not switch.SWC.is_inited:
        flags.add(Flags.SWC_NOT_INITIALIZED)

    return flags


# Создание json ошибки для отправки клиенту
def create_error(debug_msg, reason: str = None, flags: set|list = None):
    flags = _parse_flags(flags)

    out = {'ok': False, 'reason': str(reason) if isinstance(reason, str) else 'Bad usage', 
            'flags': [str(iter)[len('Flags.'):] for iter in flags]}

    # Если включена отладка, то добавляется отладочное сообщение
    if webapi.debug:
        out['debug'] = debug_msg

    return out


# Создание положительного результата
def create_result(data, flags: set|list = None):
    flags = _parse_flags(flags)

    return {'ok': True, 'data': data, 'flags': [str(iter)[len('Flags.'):] for iter in flags]}


# Инициализация путей для интерфейса управления коммутатором
# Статичные ресурсы (картинки, скрипты) 
@webapi.route("/simple/<path:path>", methods = ['GET'])
def web_entry_assets(path):
    return send_from_directory('simple', path)


# html страничка (GET) и обработка запросов (POST)
@webapi.route("/simple", methods = ['GET']) 
def web_entry_main():
    return send_from_directory('simple', 'main.html')


@webapi.errorhandler(404)
@webapi.errorhandler(405)
def web_not_found(exc):
    return create_error('Запрос не корректен')


# Обработка запросов (POST)
@webapi.route("/api/v0/", methods = ['POST']) 
def web_apiV0():
    try:
        # Получаем json
        try:
            json = request.get_json()
        except Exception as exc:
            return create_error('Ожидался JSON в POST запросе: ' + str(exc))

        # Определяемся с тем, чего хочет клиент
        action = json.get('action')

        if not action or not isinstance(action, str):
            return create_error('Параметр action должен быть, и быть строкой')

        # Добываем сессию
        session = json.get('session')
        if not session:
            session = request.cookies.get('swc_session')
        elif not isinstance(session, str):
            return create_error('Переданная в json сессия (session), должна быть строкой. Получено: ' + str(session))
        
        swc_is_inited = isinstance(switch.SWC, switch.SwitchCore) and switch.SWC.is_inited
        flags = set()
        data = {}

        match action:
            case "status":
                if not swc_is_inited:
                    data['state'] = 'need_init'
                else:
                    data['state'] = 'OK'

                return create_result(data, flags)

            case "init_swc":
                return web_action_init_swc()

        if not swc_is_inited:
            return create_error("Ядро коммутатора не загружено")

        match action:
            case "get_port_configuration":
                return switch.SWC.get_ports()

            case "create_bridge":
                br_name = json.get("br_name")
                if not br_name:
                    return create_error('Отсутствует параметр br_name')
                return switch.SWC.create_bridge(br_name)

            case "remove_bridge":
                br_name = json.get("br_name")
                if not br_name:
                    return create_error('Отсутствует параметр br_name')
                return switch.SWC.remove_bridge(br_name)

            case "add_port_to_bridge":
                port_name = json.get("port_name")
                if not port_name:
                    return create_error('Отсутствует параметр port_name')

                br_name = json.get("br_name")
                if not br_name:
                    return create_error('Отсутствует параметр br_name')

                return switch.SWC.add_port_to_bridge(port_name, br_name)

            case "remove_port_from_bridge":
                port_name = json.get("port_name")
                if not port_name:
                    return create_error('Отсутствует параметр port_name')

                return switch.SWC.remove_port_from_bridge(port_name)

            case _:
                return create_error('Отсутствует обработчик для запроса action='+action)

    except Exception as exc:
        return create_error('Необработанная ошибка при обработке POST запроса: ' + str(type(exc)) + ' -> ' + str(exc) + '\n' + traceback.format_exc(), flags=[Flags.BUG])


# Инициализация ядра коммутатора
def web_action_init_swc():
    if switch.SWC:
        return create_error("Уже инициализировано")

    switch.SWC = switch.SwitchCore(virtual_ports=24)
    return create_result("Будет сделано")