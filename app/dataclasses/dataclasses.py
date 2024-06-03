from dataclasses import dataclass
from typing import Union

@dataclass
class PSPorts:
    name: str
    max_mac: int
    cur_mac: int
    trap: bool
    address_mode:str
    status: bool
    
@dataclass
class ACL:
    name: str 
    rules: Union[None, int]  #None or count
    
@dataclass
class ACLRules:
    rule_id: int   
    allow: int  #  1 - allow, 0 - drop
    s_ip: Union[None, str]
    d_ip: Union[None, str]
    protocol: Union[None, str]
    p_src: Union[None, str]
    d_src: Union[None, str]
    
@dataclass
class ACLBinding:
    acl_name: str
    port: str
    direction: str # only ingress
    
@dataclass
class PortDHCP:
    port: str
    dhcp_snooping: bool
    
@dataclass
class DHCPServer:
    address: str
    
@dataclass
class ARPTable:
    ip: str
    mac: str
    
@dataclass
class ARP:
    port: str
    arp: bool