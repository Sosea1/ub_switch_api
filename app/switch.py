import threading
import time
import re
import pathlib
from . import simple_interface

SWC = None

class SwitchCore:
    # virtual_ports - используется для откладки, создаёт виртуальные порты, которые можно связать с доступными физическими
    def __init__(self, virtual_ports = 0):
        self.is_inited = False
        self.need_shutdown = False
        self.is_alive = True
        self._mutex = threading.Lock()
        self._config = {}
        self._last_packets_view = {}

        if virtual_ports < 0:
            raise RuntimeError("Количество virtual_ports < 0")

        # Здесь необходимо проверить конфигурацию OpenVSwitch и nftables,
        # касаемо виртуальных портов

        # Запуск рабочего потока
        self._thread_loop = threading.Thread(target=self._run)
        self._thread_loop.start()

        while self._thread_loop.is_alive and not self.is_inited:
            time.sleep(0.001)

        if not self._thread_loop.is_alive:
            self.is_inited = False
            raise RuntimeError("Ошибка запуска потока ядра коммутатора")

    def __del__():
        self.need_shutdown = True
        for milisecond in range(10000):
            if not self.is_alive:
                break
            time.sleep(0.001)

        if self.is_alive:
            print("WatchDog: поток ядра коммутатора не завершил работу вовремя")
            
    # Возвращает конфигурацию портов и их состояние в виде словаря
    def get_ports(self) -> dict:
        activity = []
        exists_ports = {}
        lines = open("/proc/net/dev", "r").readlines()[2:]
        for line in lines:
            match = re.match(r"^ *([\w\d\-_]+): +\d+ +(\d+)", line)
            if not match:
                continue

            dev = match[1]
            packets = int(match[2])
            exists_ports[dev] = False

            if dev not in self._last_packets_view or packets != self._last_packets_view[dev]:
                activity.append(dev)
                self._last_packets_view[dev] = packets

        device_up = set()
        devs = pathlib.Path("/sys/class/net/")
        for dir in devs.iterdir():
            if "down" not in open(dir / "operstate", "r").readline():
                device_up.add(dir.name)
                exists_ports[dir.name] = True

        to_delete = []
        for iter in self._last_packets_view:
            if iter not in device_up:
                to_delete.append(iter)

        for iter in to_delete:
            del self._last_packets_view[iter]

        return simple_interface.create_result({"virtual_ports": 24, "ports_states": exists_ports, "ports_activity": activity})

    # Присоединяет свободный физический порт к виртуальному
    def bind_virtual_port(self, virtual_id, eth_name):
        pass

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