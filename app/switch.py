import threading
import time
import re
import pathlib
import subprocess
from . import simple_interface

SWC = None

class SwitchCore:
    # debug_port - порт, который используется для моста между хостом и виртуальной машиной
    def __init__(self, debug_port = "enp1s0", virtual_ports = 0):
        self.is_inited = False
        self._is_created = False
        self.need_shutdown = False
        self.is_alive = True
        self._mutex = threading.Lock()
        self._config = {}
        self._last_packets_view = {}
        self._virtual_ports = virtual_ports
        self._debug_port = debug_port
        self._offline_ports = [debug_port, 'lo', 'ovs-system']
        self._update_id = 2

        # Удаляем мосты и виртуальные интерфейсы
        #self.splitCommandToTable(self.vsctl(['show']).split('\n'))

        # self.vsctl(['del-br', 'dummy_switch'])
        # self.vsctl(['add-br', 'dummy_switch'])

        # # Создаём виртуальные порты
        # for iter in range(virtual_ports):
        #     self.vsctl(['add-port', 'dummy_switch', f'ether{iter}', '--', 'set', 'interface', f'ether{iter}', 'type=internal'])

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

        for milisecond in range(10000):
            if not self.is_alive:
                break

            time.sleep(0.001)

        if self.is_alive:
            print("WatchDog: поток ядра коммутатора не завершил работу вовремя")
            

    def run_cmd(self, cmd_args = []):
        output = subprocess.Popen(cmd_args, stdout=subprocess.PIPE)
        return output.communicate()[0].decode()


    def ip(self, args = []):
        return self.run_cmd(['ip'] + args)


    def vsctl(self, args = []):
        return self.run_cmd(['ovs-vsctl'] + args)


    def vsctl_get_bridges(self) -> list:
        bridges = []
        table = self.splitCommandToTable(self.vsctl(['show']).split('\n'))
        table = table[next(iter(table))]
        for key in table:
            args = key.split(' ')
            if args[0] != 'Bridge':
                continue

            br_name = args[1]
            if br_name[0] == '"':
                br_name = br_name[1:-1]

            bridges.append(br_name)

        return bridges


    def get_allPorts(self) -> list:
        ports = set()
        devs = pathlib.Path("/sys/class/net/")
        for dir in devs.iterdir():
            if(dir.name in self._offline_ports):
                continue

            ports.add(dir.name)

        devs = self.vsctl_get_bridgedPorts()
        for key in devs:
            for port in devs[key]:
                if(port in self._offline_ports):
                    continue

                ports.add(port)


        return list(ports)


    def vsctl_get_bridgedPorts(self) -> dict:
        groups = {}

        table = self.splitCommandToTable(self.vsctl(['show']).split('\n'))
        table = table[next(iter(table))]
        for key in table:
            args = key.split(' ')
            if args[0] != 'Bridge':
                continue

            bridge = []
            for port in table[key]:
                args2 = port.split(' ')
                if args2[0] != 'Port':
                    continue

                port_name = args2[1]
                if port_name[0] == '"':
                    port_name = port_name[1:-1]
                    
                bridge.append(port_name)

            br_name = args[1]
            if br_name[0] == '"':
                br_name = br_name[1:-1]

            groups[br_name] = bridge

        return groups


    def vsctl_get_freeports(self) -> list:
        allPort = set(self.get_allPorts())
        bridged = self.vsctl_get_bridgedPorts()

        for key in bridged:
            allPort = allPort.difference(set(bridged[key]))

        return list(allPort)


    def splitCommandToTable(self, lines: list):
        iter = 0
        table = {}

        while iter < len(lines):
            begin = iter

            if len(lines[iter]) == 0:
                break

            iter += 1

            while iter < len(lines):
                if len(lines[iter]) == 0 or lines[iter][0] != ' ':
                    break

                iter += 1

            iter -= 1

            if begin == iter:
                args = lines[begin].split(': ')
                if len(args) == 1:
                    table[lines[begin]] = 'nil'
                else:
                    table[args[0]] = args[1]
            else:
                subList = lines[begin+1:iter+1]
                for sub_line in range(len(subList)):
                    subList[sub_line] = subList[sub_line][4:]

                table[lines[begin]] = self.splitCommandToTable(subList)
            
            iter += 1
            
        return table


    # Возвращает конфигурацию портов и их состояние в виде словаря
    # { states: {"eth0": 1, "eth1": 0, "eth2": 2}, -- eth0=up, eth1=down, eth2=под влиянием stp
    #   activity: ["eth0"], -- Если за последнюю секунду был трафик в данном порту
    #   groups: {"bridge1": ["eth0", "eth1"]}, -- Объединённые интерфейсы
    #   update_id: 1234567 -- id текущей смены конфигурации портов, увеличивается при переключении состояния портов
    # }
    #
    def get_ports(self) -> dict:
        activity = []       # Список активных портов
        states = {}         # Таблица состояний портов
        groups = {}         # Группы интерфейсов
        
        groups = self.vsctl_get_bridgedPorts()
        groups['*'] = self.vsctl_get_freeports()

        # Считываем кодичество пакетов, прошедших через порты для определения активности
        lines = open("/proc/net/dev", "r").readlines()[2:]
        for line in lines:
            match = re.match(r"^ *([\w\d\-_]+): +\d+ +(\d+)", line)
            if not match:
                continue

            dev = match[1]  # Устройство
            packets = int(match[2]) # Количество пакетов

            # Запись о количестве пакетов порта не найдена, либо количество пакетов изменилось
            contains = dev in self._last_packets_view
            if not contains or packets != self._last_packets_view[dev]:
                if contains:
                    activity.append(dev)

                self._last_packets_view[dev] = packets

        # Сбор информации о состоянии портов
        devs = pathlib.Path("/sys/class/net/")
        for dir in devs.iterdir():
            if "down" not in open(dir / "operstate", "r").readline():
                states[dir.name] = 1   # Порт действует/работает и/или включен
            else:
                states[dir.name] = 0   # Порт отключён

            if dir.name in groups:
                states[dir.name] += 4

        for port in self.get_allPorts():
            if port not in states:
                states[port] = 0

        # Если найдётся запись о количестве пакетов для несуществующего порта, то она будет удалена
        to_delete = []
        for iter in self._last_packets_view:
            if iter not in states:
                to_delete.append(iter)

        for iter in to_delete:
            del self._last_packets_view[iter]

        for key in self._offline_ports:
            if key in states:
                del states[key]
            if(key in activity):
                activity.remove(key)

        return simple_interface.create_result({"update_id": self._update_id, "states": states, "groups": groups, "activity": activity})

    # Создать группу
    def create_bridge(self, br_name: str):
        bridges = self.vsctl_get_bridges()
        if br_name in bridges or br_name in self._offline_ports:
            return simple_interface.create_error(f'Имя нового моста пересекается с существующим: {br_name}')

        out = self.vsctl(['add-br', br_name])
        self._update_id += 1

        return simple_interface.create_result({})

    # Удалить группу
    def remove_bridge(self, br_name: str):
        bridges = self.vsctl_get_bridges()
        if br_name not in bridges or br_name in self._offline_ports:
            return simple_interface.create_error(f'Мост не существует: {br_name}')

        out = self.vsctl(['del-br', br_name])
        self._update_id += 1

        return simple_interface.create_result({})

    # Добавить порт в группу
    def add_port_to_bridge(self, port_name: str, br_name: str):
        ports = self.vsctl_get_freeports()
        bridges = self.vsctl_get_bridges()

        if port_name not in ports or port_name in self._offline_ports:
            return simple_interface.create_error(f'Порт не может быть сгруппирован, он занят: {port_name}')

        if br_name not in bridges:
            return simple_interface.create_error(f'Порт не добавлен, группа отсутствует: {br_name}')

        out = self.vsctl(['add-port', br_name, port_name])
        self._update_id += 1

        return simple_interface.create_result({})

    # Удалить порт из группы
    def remove_port_from_bridge(self, port_name: str):
        ports = self.vsctl_get_freeports()

        if port_name in ports or port_name in self._offline_ports:
            return simple_interface.create_error(f'Порт не находится в группе: {port_name}')

        self.vsctl(['del-port', port_name])
        self._update_id += 1

        return simple_interface.create_result({})


    # Функция рабочего потока
    def _run(self):
        self.is_inited = True

        while True:
            time.sleep(1)
            if self.need_shutdown:
                break

        self.is_alive = False

    # Загрузить конфигурацию
    def load_config(self, config: dict):
        pass

    # Сохранить конфигурацию
    def save_config(self) -> dict:
        pass