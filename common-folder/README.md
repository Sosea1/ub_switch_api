# API для управления OpenVSwitch
## Python Flask
API посторен на базе Flask, что позволяет достаточно легко создавать запросы
```python
@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"
```
В **app.route("/")**  указываем путь для запроса, далее возвращаем ответ **return "Hello, World!"** </br>
Flask по стандарту использует метод GET для своих запросов(можно для них не прописывать метод)</br>
Если нужно указать метод, или список методов то добавляем аргумент **methods**</br>
Например:
```python
@app.route("/ovs/get-schema", methods = ['GET'])
def route_ovs_get_schema():
    import Tests.utils
    return Tests.utils.makeRequest('tcp:127.0.0.1:6640', 'get_schema', ['Open_vSwitch']).result
```
## Работа с командами OpenVSwitch
Для работы с настройками OpenVSwitch используется ovs-vsctl, по сути это тот же самый метод командной строки. Список команд можно посмотреть в официальной документации http://www.openvswitch.org/support/dist-docs/ovs-vsctl.8.txt и https://docs.openvswitch.org/en/latest/faq/configuration/ </br>
Чтобы подключить библиотеку:
```python
from ovs_vsctl import VSCtl
```
Тогда вызвать комманду можно так:
```python
def route_ovs_vsctl_add_bridge():
    bridge = request.args.get('bridge')
    if(bridge == None):
        return "specify bridge"
    vsctl = VSCtl('tcp', '127.0.0.1', 6640)
    result = vsctl.run('add-br '+ bridge, 'list', 'json')
    return "bridge "+bridge+" has been added"
```
## Настройка и решение проблем с OpenVSwitch
Установка OpenVSwitch:</br>
```
sudo apt-get install openvswitch-switch
```
Открытие принимающего сокета к базе данных OpenVSwitch
```
ovs-vsctl set-manager ptcp:6640
```
Для того, чтобы с устройства с OpenVSwitch можно было пинговаться нужно ввести следующие команды:
```
ip addr flush dev eth0
ip addr add 192.168.128.5/24 dev br0
ip link set br0 up
```
где eth0 - интерфейс</br>
а br0 - мост OVS 
