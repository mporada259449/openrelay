import socket
from smtplib import SMTP
import argparse
def isOpenRelay(address, port, from_addr, to_addr, message):
    with SMTP(host = address, port=port, timeout=10) as smtp:
        try:
            ans = smtp.ehlo("example.org")
        except socket.timeout:
            print("Cannot connect to server")
        if int(ans[0])==250:
            try:
                ans = smtp.sendmail(from_addr = from_addr, to_addrs = to_addr, msg=message)
                #zwraca dictionary hostów które nie dostały maila 
                return True
            except:
                return False


def connectToServer(address, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((address,port))
        ans = sock.recv(1024)
        ans = ans.decode("utf-8")
        return ans
    except socket.timeout:
        print("Conetction on this port is not possible, port is closed or filtered")
    except:
        print("ERROR")            


if __name__=="__main__":
    parser = argparse.ArgumentParser(description="Program pozwala na wykrywanie czy serwer SMTP jest open relay")
    parser.add_argument("-a", help="Adres serwera", type=str, required=True)
    parser.add_argument("-p", help="Port serwera SMTP", default=25, type=int)
    parser.add_argument("--from_addr", help="Adres źródłowy maila użyty w teście", type=str, default="antispam@example.org")
    parser.add_argument("--to_addr", help="Adres docelowy maila użyty w teście", type=str, default="test@example.com")
    parser.add_argument("--msg", help="Wiadmość wysłana w testowym mailu", type=str, default="test message")
    args = parser.parse_args()
    address = socket.gethostbyname(args.a)
    port = args.p
    result = connectToServer(address=address, port=port) 
    if result[:3]=="220":
        ans = isOpenRelay(address=address, port=port, from_addr=args.from_addr, to_addr=args.to_addr, message=args.msg)
        if ans:
            print("Server is open relay")
        else:
            print("Server is not open relay")