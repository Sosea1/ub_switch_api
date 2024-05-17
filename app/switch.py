import threading
import time
import re
import pathlib
import subprocess
from . import simple_interface
import hashlib
import traceback
import json
import os
from app import SockIO

SWC = None

class SwitchCore:
    # debug_port - порт, который используется для моста между хостом и виртуальной машиной
    def __init__(self, debug_port = "enp1s0"):
        self.is_inited = False          # Флаг, отмечающий запуск внутреннего потока  
        self._is_created = False        # Флаг, отмечающий полное выполнение конструктора
        self.need_shutdown = False      # Если вызван деструктор, требование к завершению потока
        self.is_alive = True            # По завершению работы потока ставится в False
        self._mutex = threading.Lock()
        self._config = {}
        self._debug_port = debug_port           # Интерфейс отладки виртуальной машины
                        # Интерфейсы, которые не будут использоваться в коммутации 
        self._excluded_ports = [debug_port, 'lo', 'ovs-system', 'docker0']
        self._excluded_ports_docker = []
        self._update_id = time.time()*100       # Счётчик обновления конфигурации портов
        self._last_packets_view = {}            # Последняя активность интерфейсов
        self._interface_activity = []           # Список активных интерфейсов на момент последней проверки (была обработка пакетов)
        self._hash_interface_configuration = "" # Хэш последней полученной конфигурации портов

        # Удаляем мосты и виртуальные интерфейсы
        #self.splitCommandToTable(self.vsctl(['show']).split('\n'))

        # self.vsctl(['del-br', 'dummy_switch'])
        # self.vsctl(['add-br', 'dummy_switch'])

        # # Создаём виртуальные порты
        # for iter in range(virtual_ports):
        #     self.vsctl(['add-port', 'dummy_switch', f'ether{iter}', '--', 'set', 'interface', f'ether{iter}', 'type=internal'])

        try:
            self._module_path = os.path.dirname(os.path.realpath(__file__))+'/main.ko'
            self.run_cmd(['rmmod', 'main.ko'])
            self.run_cmd(['insmod', self._module_path])
            output = self.run_cmd(['bash', '-c', 'lsmod | grep main'])
            self._is_module_loaded = len(output) > 0
        except Exception as exc:
            self._is_module_loaded = False
            print(f"Не удалось установить модуль ядра {str(exc)}")

        # Запуск рабочего потока
        self._thread_loop = threading.Thread(target=self._run)
        self._thread_loop.start()

        while self._thread_loop.is_alive and not self.is_inited:
            time.sleep(0.001)

        if not self._thread_loop.is_alive:
            self.is_inited = False
            raise RuntimeError("Ошибка запуска потока ядра коммутатора")

        self._is_created = True

    def __del__(self):
        self.need_shutdown = True

        if not self._is_created:
            return

        for milisecond in range(10000): # Ожидаем 10 секунд пока поток не завершит работу
            if not self.is_alive:
                break

            time.sleep(0.001)

        try:
            self.run_cmd(['rmmod', 'main.ko'])
        except:
            pass
        
        if self.is_alive:
            print("WatchDog: поток ядра коммутатора не завершил работу вовремя")
            
    # Фильтрует/отклоняет системные порты
    def isCorePort(self, port_name: str):
        return port_name in self._excluded_ports or port_name in self._excluded_ports_docker


    def run_cmd(self, cmd_args = []):
        output = subprocess.Popen(cmd_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return output.communicate()[0].decode()+output.communicate()[1].decode()

    def cmd_vsctl(self, args = []):
        return self.run_cmd(['ovs-vsctl'] + args)

    # Сведения о мостах и их портах {"bridge_name": {"port1": {"tag": 6}, "port2": {}}}
    def cmd_vsctl_show(self) -> dict:
        lines = self.cmd_vsctl(['show']).split('\n')
        lines_next = []

        dhcp_snoop_list = self.kernel_dhcp_snooping_read()

        # f4e57597-4dc4-44c6-bc02-25e09c67157e
        #     Bridge "Test"
        #         Port "Test"
        #             tag: 6
        #             Interface "Test"
        #                 type: internal
        #         Port enp9s0
        #             Interface enp9s0
        #         Port enp10s0
        #             Interface enp10s0
        #     ovs_version: "3.1.0"

        # Избавляемся от первого вложения (f4e57597-4dc4-44c6-bc02-25e09c67157e)
        for line in lines:
            if len(line) < 5 or not line.startswith(' '*4):
                continue

            lines_next.append(line[4:])

        # Считываем верхние группы (Bridge Test)
        def read_sub_groups(lines, group_name):
            group_name += ' '
            iter = -1
            group_lines = {}
            while iter < len(lines)-1:
                iter += 1
                begin = iter # Позиция начала группы (Bridge Test)
                while iter < len(lines)-1:
                    iter += 1
                    if lines[iter][0] != ' ': # Нашли новое объявление группы
                        iter -= 1 # Отступаем, указываем на последнюю строчку группы
                        break

                if not lines[begin].startswith(group_name): # Если эта группа не является объявлением моста (ovs_version: "3.1.0")
                    continue

                bridge = lines[begin][len(group_name):] # Название моста
                if bridge[0] == '"':
                    bridge = bridge[1:-1] # Избавляемся от кавычек

                # Изымаем группу, не включая название моста, с урезанием пробелов
                group_lines[bridge] = [line[4:] for line in lines[begin+1:iter+1]]

            return group_lines

        bridge_lines = read_sub_groups(lines_next, 'Bridge')

        out = {}
        # Считываем порты (Port Test)
        for bridge in bridge_lines:

            # Исключаем не нужные интерфейсы
            if self.isCorePort(bridge):
                continue

            lines = bridge_lines[bridge]
            port_lines = read_sub_groups(lines, 'Port')

            ports = {}

            for port_config_key in port_lines:
                # Исключаем не нужные интерфейсы
                if self.isCorePort(port_config_key):
                    continue

                port_config_lines = port_lines[port_config_key]
                port_config_out = {}

                for line in port_config_lines:
                    reg = re.match(r'^tag: (\d+)$', line)
                    if reg:
                        port_config_out['vlan_access'] = reg[1]

                    reg = re.match(r'^trunks: \[(.*)\]$', line)
                    if reg:
                        port_config_out['vlan_trunks'] = [int(tag) for tag in reg[1].split(', ')]

                if port_config_key in dhcp_snoop_list:
                    port_config_out['dhcp_snoop'] = True

                ports[port_config_key] = port_config_out

            out[bridge] = ports

        return out
        
    # Список портов, подключенных к мостам ["Port1", "Port2"]
    def cmd_vsctl_show_onlyPorts(self) -> set:
        bridges = self.cmd_vsctl_show()
        out = set()
        for key in bridges:
            for port in bridges[key]:
                out.add(port)

        return out

    # Список мостов ["Bridge1", "Bridge2"]
    def cmd_vsctl_show_onlyBridges(self) -> set:
        bridges = self.cmd_vsctl_show()
        out = set()
        for key in bridges:
            out.add(key)

        return out


    def ip(self, args = []):
        return self.run_cmd(['ip'] + args)

    # Выводит список всех существующих интерфейсов ["Port1", "Port2"]
    def sys_all_exists_ports(self) -> set:
        ports = set()
        devs = pathlib.Path("/sys/class/net/")

        # Сначала определим не нужные порты (docker)
        new_excluded = set()

        for dir in devs.iterdir():
            if open(dir / "address", "r").readline().startswith("02:42"):
                new_excluded.add(dir.name)

            for dir2 in dir.iterdir():

                if not dir2.name.startswith("upper_"):
                    continue

                if open(dir2 / "address", "r").readline().startswith("02:42"):
                    new_excluded.add(dir.name)

        self._excluded_ports_docker = new_excluded

        for dir in devs.iterdir():
            # Исключаем не нужные порты
            if self.isCorePort(dir.name):
                continue

            ports.add(dir.name)

        devs = self.cmd_vsctl_show()
        for key in devs:
            ports.union(set(devs[key].keys()))

        return ports


    # Возвращает список портов не связанных мостами
    def cmd_vsctl_get_freeports(self) -> list:
        allPort = set(self.sys_all_exists_ports())
        bridged = self.cmd_vsctl_show()

        for key in bridged:
            allPort = allPort.difference(set(bridged[key].keys()))

        return list(allPort)

    # Возвращает текущее состояние портов
    # {"port1": 1, "port2": 0, "port3": 2, "port4": -1} -- eth0=up, eth1=down, eth2=отправка пакетов отключена (learning), eth4=не найден
    def get_interfaces_state(self) -> dict:
        states = {}

        # Сбор информации о состоянии портов
        devs = pathlib.Path("/sys/class/net/")
        for dir in devs.iterdir():
            name = dir.name
            if self.isCorePort(name):
                continue # Пропускаем не нужные порты

            if "down" not in open(dir / "operstate", "r").readline():
                states[name] = 1   # Порт действует/работает и/или включен
            else:
                states[name] = 0   # Порт отключён

        return states

    # Возвращает текущую конфигурацию портов
    # {port1: {state: 1, bridge: ""}} -- bridge - интерфейс моста, если есть
    def get_interfaces_configuration(self) -> dict:
        configuration = self.get_interfaces_state()
        bridges_groups = self.cmd_vsctl_show()

        for port in configuration.keys():
            configuration[port] = {"state": configuration[port]} # Переносим состояние в переменную

            # Находим какому мосту принадлежит порт
            for bridge in bridges_groups:
                if port in bridges_groups[bridge]:
                    configuration[port]["bridge"] = bridge
                    configuration[port].update(bridges_groups[bridge][port])

        # Добавляем отсутствующие, но упоминающиеся порты
        for br in bridges_groups:
            for port in bridges_groups[br]:
                if port not in configuration:
                    configuration[port] = {"state": -1}

        # Чтение конфигурации DHCP snooping
        for dev in self.kernel_dhcp_snooping_read():
            if dev in configuration:
                configuration[dev]['dhcp_snoop'] = True

        # Если хеш не сошёлся не сошёлся, значит конфигурация изменилась
        hash = self.md5(json.dumps(configuration).encode())
        if self._hash_interface_configuration != hash: 
            self._hash_interface_configuration = hash
            self._update_id += 1

        return configuration
        
    def kernel_dhcp_snooping_read(self):
        try:
            fd = open('/dev/little_firewall', 'r')
            devs = fd.read()
            devs = devs.split('\0')[:-1]
            fd.close()

            return set(devs)
        except Exception as exc:
            return []

    def kernel_dhcp_snooping_write(self, devs: set):
        devs = list(set(devs))

        fd = open('/dev/little_firewall', 'w')
        fd.write('\0'.join(devs)+'\0')
        fd.close()


    # Возвращает конфигурацию портов и их состояние в виде словаря
    # { configuration: {} -- Если update_id клиента просрочен
    #   groups: {"bridge1": ["eth0", "eth1"]}, -- Объединённые интерфейсы
    #
    #   activity: ["eth0"], -- Интерфейсы на которых недавно проходил трафик
    #   update_id: 1234567 -- id текущей смены конфигурации портов, увеличивается при изменении состояния портов
    # }
    def get_ports(self, client_update_id: int) -> dict:
        out = {"update_id": self._update_id, "activity": self._interface_activity}
        out["kernel_support"] = self._is_module_loaded

        if self._update_id != client_update_id:
            out["configuration"] = self.get_interfaces_configuration()
            vs_show = self.cmd_vsctl_show()
            out["groups"] = {}
            for key in vs_show:
                out["groups"][key] = list(vs_show[key].keys())

            out["groups"]["*"] = self.cmd_vsctl_get_freeports()

        return simple_interface.create_result(out)

    # Активировать или отключить интерфейс
    def port_set_enable_state(self, port_name: str, state: bool):
        if self.isCorePort(port_name):
            return simple_interface.create_error(f'Порт не существует: {port_name}')

        self.run_cmd(['ip', 'link', 'set', 'dev', str(port_name), 'up' if state else 'down'])
        return simple_interface.create_result({})

    # Активировать или отключить dhcp snooping
    def port_set_dhcp_snooping_state(self, port_name: str, state: bool):
        if self.isCorePort(port_name):
            return simple_interface.create_error(f'Порт не существует: {port_name}')

        devs = self.kernel_dhcp_snooping_read()
        port_name = port_name.replace('\0', '\n')
        if state:
            devs.add(port_name)
        else:
            devs.remove(port_name)
        self.kernel_dhcp_snooping_write(devs)

        return simple_interface.create_result({})


    # Создать группу
    def create_bridge(self, br_name: str):
        bridges = self.cmd_vsctl_show_onlyBridges()
        if br_name in bridges:
            return simple_interface.create_error(f'Имя нового моста пересекается с существующим: {br_name}')

        if not self.isValidInterfaceName(br_name):
            return simple_interface.create_error(f'Имя нового моста недопустимо: {br_name}')

        output = self.cmd_vsctl(['add-br', br_name])
        if len(output) > 0:
            return simple_interface.create_error(output)
        self._update_id += 1

        return simple_interface.create_result({})

    # Удалить группу
    def remove_bridge(self, br_name: str):
        bridges = self.cmd_vsctl_show_onlyBridges()
        if br_name not in bridges or self.isCorePort(br_name):
            return simple_interface.create_error(f'Мост не существует: {br_name}')

        output = self.cmd_vsctl(['del-br', br_name])
        if len(output) > 0:
            return simple_interface.create_error(output)
        self._update_id += 1

        return simple_interface.create_result({})

    # Добавить порт в группу
    def add_port_to_bridge(self, port_name: str, br_name: str):
        ports = self.cmd_vsctl_get_freeports()
        bridges = self.cmd_vsctl_show_onlyBridges()

        if port_name not in ports or self.isCorePort(port_name):
            return simple_interface.create_error(f'Порт не может быть сгруппирован, он занят: {port_name}')

        if br_name not in bridges:
            return simple_interface.create_error(f'Порт не добавлен, группа отсутствует: {br_name}')

        output = self.cmd_vsctl(['add-port', br_name, port_name])
        if len(output) > 0:
            return simple_interface.create_error(output)
        self._update_id += 1

        return simple_interface.create_result({})

    # Удалить порт из группы
    def remove_port_from_bridge(self, port_name: str):
        ports = self.cmd_vsctl_get_freeports()

        if port_name in ports or self.isCorePort(port_name):
            return simple_interface.create_error(f'Порт не находится в группе: {port_name}')

        output = self.cmd_vsctl(['del-port', port_name])
        if len(output) > 0:
            return simple_interface.create_error(output)
        self._update_id += 1

        return simple_interface.create_result({})

    # Задание access тэга
    def vlan_set_access_tag(self, port: str, tag: int):
        bridget_ports = self.cmd_vsctl_show_onlyPorts()
        if port not in bridget_ports or self.isCorePort(port):
            return simple_interface.create_error(f'Порт не существует или не находится в мосте: {port}')

        output = self.cmd_vsctl(['set', 'port', port, f'tag={int(tag)}'])
        if len(output) > 0:
            return simple_interface.create_error(output)
        self._update_id += 1
        return simple_interface.create_result({})

    # Задание транков
    def vlan_set_trunk_tags(self, port: str, tags: list):
        bridget_ports = self.cmd_vsctl_show_onlyPorts()
        if port not in bridget_ports or self.isCorePort(port):
            return simple_interface.create_error(f'Порт не существует или не находится в мосте: {port}')

        trunks = ','.join([str(int(iter)) for iter in tags])
        output = self.cmd_vsctl(['set', 'port', port, f'trunk={trunks}'])
        if len(output) > 0:
            return simple_interface.create_error(output)
        self._update_id += 1
        return simple_interface.create_result({})

    # Убрать VLan с порта
    def vlan_set_untagged_native(self, port: str):
        bridget_ports = self.cmd_vsctl_show_onlyPorts()
        if port not in bridget_ports or self.isCorePort(port):
            return simple_interface.create_error(f'Порт не существует или не находится в мосте: {port}')
        
        output = self.cmd_vsctl(['clear', 'port', port, 'tag', 'trunk'])
        if len(output) > 0:
            return simple_interface.create_error(output)

        self._update_id += 1
        return simple_interface.create_result({})


    def md5(self, data: str):
        sha = hashlib.md5(data)
        return sha.hexdigest()

    def isValidInterfaceName(self, name: str):
        return re.match(r'^[\w\d_]{,16}$', name) and not self.isCorePort(name)

    # Проверка активности интерфейсов
    def _check_interface_activity(self):
        activity = []
        last_activity = self._last_packets_view

        # Считываем количество пакетов, прошедших через порты для определения активности

        #Inter-|   Receive                                                |  Transmit
        # face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
        #    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
        #enp1s0: 22487403  131264 9941    0    0  9941          0         0 20831652  124711    0    0    0     0       0          0

        lines = open("/proc/net/dev", "r").readlines()[2:]
        devs = set()
        for line in lines:
            match = re.match(r"^ *([\w\d\-_]+): +\d+ +(\d+)", line)
            if not match:
                continue

            dev = match[1]  # Устройство

            if self.isCorePort(dev):
                continue # Пропускаем не нужные порты

            devs.add(dev)
            packets = int(match[2]) # Количество пакетов

            # Запись о количестве пакетов порта не найдена, либо количество пакетов изменилось
            contains = dev in last_activity
            if not contains or packets != last_activity[dev]:
                if contains:
                    activity.append(dev)

                last_activity[dev] = packets

        # Если найдётся запись о количестве пакетов для несуществующего порта, то она будет удалена
        to_delete = []
        for iter in last_activity:
            if iter not in devs:
                to_delete.append(iter)

        # Удаляем отсутствующие порты
        for iter in to_delete:
            del last_activity[iter]

        self._last_packets_view = last_activity
        self._interface_activity = activity

    # Функция рабочего потока
    def _run(self):
        self.is_inited = True
        configuration = {}

        while True:
            time.sleep(1)
            if self.need_shutdown:
                break

            try:
                self._check_interface_activity()
                configuration = self.get_interfaces_configuration() # Проверка текущей конфигурации устройств
            except Exception as exc:
                print(str(exc) + '\n' + traceback.format_exc())

            # try:
            #     SockIO.emit("status", configuration)
            # except Exception as exc:
            #     print(f"Ошибка при отправке данных веб сокету {str(exc)}")

        self.is_alive = False

    # Загрузить конфигурацию
    def load_config(self, config: dict):
        pass

    # Сохранить конфигурацию
    def save_config(self) -> dict:
        pass