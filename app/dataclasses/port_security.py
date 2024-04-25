from dataclasses import dataclass
from app import ma


@dataclass
class PSPorts:
    name: str
    max_mac: int
    cur_mac: int
    trap: bool
    address_mode:str
    status: bool
    
class PSPortsSchema(ma.Schema):
    class Meta:
        fields = ("name", "max_mac", "cur_mac", "trap", 
                  "address_mode", "status")
        
ps_port = PSPortsSchema()
ps_ports = PSPortsSchema(many=True)