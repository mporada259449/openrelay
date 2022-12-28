from scapy.all import *

class Scanner():
    def __init__(self) -> None:
        self.openports = []

    def portscanner(self, ip):
        port_list = [53, 123]
        for port in port_list:
            udp_packet = IP(dst = ip)/UDP(dport = port, sport = 49456 )
            result =  sr1(udp_packet, verbose = 0 , timeout = 1)
            if result is None:
                self.openports.append(port)

    
if __name__=="__main__":
    scanner = Scanner()
    scanner.portscanner("127.0.0.1")
    print(scanner.openports)

