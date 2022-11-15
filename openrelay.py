import socket
from smtplib import SMTP

def isOpenRelay(address, port):
    with SMTP(host = address, port=port, timeout=10) as smtp:
        try:
            ans = smtp.ehlo("example.org")
        except socket.timeout:
            print("Cannot connect to server")
        if int(ans[0])==250:
            try:
                ans = smtp.sendmail(from_addr="antispam@example.org", to_addrs="259449@studnet.pwr.edu.pl", msg="test open relay")
                #zwraca dictionary hostów które nie dostały maila 
                return True
            except:
                return False


address = input("Address or domain name: ")
port = input("Port number: ")
address = socket.gethostbyname(address)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(5)

try:
    sock.connect((address,int(port)))
    ans = sock.recv(1024)
    ans = ans.decode("utf-8")
    if ans[:3]=="220":
        ans = isOpenRelay(address,port)
        if ans:
            print("server is open relay")
        else:
            print("server is not open relay")
except socket.timeout:
    print("Conetction on this port is not possible, port is closed or filtered")
except:
    print("ERROR")            



