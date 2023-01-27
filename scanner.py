from scapy.all import *
from scapy.layers import dns, ntp, tftp
import argparse
class Scanner():
    def dnsamplifcation(self, ip, n = 30, domain = "google.com"):
        query_type = ["ANY", "A", "AAAA", "CNAME", "MX"]
        for query in query_type:
            dns_packet = IP(dst = ip)/UDP(dport=53)/dns.DNS(rd = 1, qd = dns.DNSQR(qname = domain, qtype = query))
            for _ in range(n):
                try:
                    result = sr1(dns_packet, verbose = False, timeout=0.2)
                except TimeoutError:
                    print(f"Host {ip} nie jest podatny na atak dla query={query}")
                    break
            if result is None:
                print(f"Host {ip} nie jest podatny na atak dla query={query}")
            else:
                print(f"Host {ip} jest podatny na atak dla query={query}")
                print("Amplification ratio: ", len(result)/len(dns_packet))

    def ntpamplifcation(self, ip, n=30):
        mode_types = [6, 3] 
        for mode in mode_types:
            ntp_packet = IP(dst = ip)/UDP(dport = 123)/ntp.NTP(mode = mode)
            for _ in range(n):
                try:
                    result = sr1(ntp_packet, verbose = False, timeout=0.2)
                except TimeoutError:
                    print(f"Host {ip} nie jest podatny na atak dla mode={mode}")
                    break
            if result is None:
                print(f"Host {ip} nie jest podatny na atak dla mode={mode}")
            else:
                print(f"Host {ip} jest podatny na atak dla mode={mode}")
                print("Amplification ratio: ", len(result)/len(ntp_packet)) 

    def tftpamplifcation(self, ip, file, n = 30 ):
        opcode_type = [1]
        for opcode in opcode_type:
            tftp_packet = IP(dst = ip)/UDP(sport = 49350, dport=69)/tftp.TFTP(op=opcode)/tftp.TFTP_RRQ(filename=file, mode = "netascii")
            tftp_packet.show()
            for _ in range(n):
                try:
                    result = sr1(tftp_packet, timeout=1)
                except TimeoutError:
                    print(f"Host {ip} nie jest podatny na atak dla opcode={opcode}")
                    break
            if result is None:
                print(f"Host {ip} nie jest podatny na atak dla opcode={opcode}")
            else:
                print(f"Host {ip} jest podatny na atak dla opcode={opcode}")
                print("Amplification ratio: ", len(result)/len(tftp_packet))


    
if __name__=="__main__":
    scanner = Scanner()
    parser = argparse.ArgumentParser(description="""Program pozwala na wykrywanie, czy serwer usługi jest podatny na atak UDP Amplification""")
    parser.add_argument("-d", help= "Sprawdzenie serwera DNS", action="store_true")
    parser.add_argument("-n", help="Sprawdzenie dla serwera NTP", action="store_true")
    parser.add_argument("-t", help="Sprawdzenie dla serwera TFTP", action="store_true")
    parser.add_argument("-a", help="Adres serwera lub domena", type=str, required=True)
    parser.add_argument("-c", help="Ilość pakietów do wysłania", type=int, default=30, required=False)
    parser.add_argument("--file", help="Nazwa pliku dla serwera TFTP", type=str, required=False)
    parser.add_argument("--domain", help="Nazwa domeny dla zapytania do serwera DNS", default="google.com", type=str, required=False)
    args = parser.parse_args()

    if args.d==args.n==args.t==False:
        print("Nie podano rodzaju usługi")

    if args.d==True:
        scanner.dnsamplifcation(ip = args.a, n = args.c, domain = args.domain)

    if args.n==True:
        scanner.ntpamplifcation(ip = args.a, n = args.c)
    if args.t==True and args.file is None:
        print("Nie podano nazwy pliku")
    elif args.t==True and args.file is not None:
        scanner.tftpamplifcation(ip = args.a, n= args.c, file = args.file)