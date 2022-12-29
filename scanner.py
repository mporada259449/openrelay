from scapy.all import *
import argparse
class Scanner():
    def dnsamplifcation(self, ip):
        query_type = ["ANY", "A", "AAAA", "CNAME", "MX"]
        #src_addr = ".".join([str(randrange(1, 255)) for _ in range(4)])
        for query in query_type:
            dns_packet = IP(dst = ip)/UDP(dport=53)/DNS(rd = 1, qd = DNSQR(qname = "google.com", qtype = query))
            """"pomysł na razie jest taki że prześle 100 pakietów na serwer jeśli dostne 100 odpowiedzi to znaczy że jest podatny, mogę też 
            policzyc do tego ratio response/request bo w sumie to daje dużą wartość"""
            for _ in range(30):
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

    def ntpamplifcation(self, ip):
        mode_types = [6, 3] 
        for mode in mode_types:
            ntp_packet = IP(dst = ip)/UDP(dport = 123)/NTP(mode = mode)
            for _ in range(30):
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

    def tftpamplifcation(self, ip):
        opcode_type = [1, 5]
        for opcode in opcode_type:
            tftp_packet = IP(dst = ip)/UDP(dport=69)/TFTP(op=opcode)
            for _ in range(30):
                try:
                    result = sr1(tftp_packet, verbose = False, timeout=0.2)
                except TimeoutError:
                    print(f"Host {ip} nie jest podatny na atak dla opcode={opcode}")
                    break
            if result is None:
                print(f"Host {ip} nie jest podatny na ataj dla opcode={opcode}")
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
    args = parser.parse_args()

    if args.d==args.n==args.t==False:
        print("Nie podano rodzaju usługi")
    if args.d==True:
        scanner.dnsamplifcation(args.a)
    if args.n==True:
        scanner.ntpamplifcation(args.a)
    if args.t==True:
        scanner.tftpamplifcation(ip = args.a)