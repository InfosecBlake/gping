import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import argparse
from OuiLookup import OuiLookup
import random
import sys
from datetime import datetime

def BANNER():
 print(r"""
      _____ _____ _____ _   _  _____ 
     / ____|  __ \_   _| \ | |/ ____|
    | |  __| |__) || | |  \| | |  __ 
    | | |_ |  ___/ | | | . ` | | |_ |
    | |__| | |    _| |_| |\  | |__| |
     \_____|_|   |_____|_| \_|\_____|"""+'\n\n')

def main():        
    parser = argparse.ArgumentParser(description='A simple command line ARP/TCP scanning tool. Use -a to perform an ARP scan on a given subnet. Use -t to perform a TCP SYN scan, ' 
                                                'if no port are selected then port 1-1024 will be scanned. Use -p to specify port. Please see the arguments for examples.')
    parser.add_argument('-a', '--arp', help='perform an arp-scan on the provided subnet or IP which will return MAC, IP, and OUI lookup. ex: gping.py -a 10.0.0.1 or gping.py -a 10.0.0.0/24')
    parser.add_argument('-t', '--tcp', help='perform a tcp-scan on the provided subnet. ex: gping.py -t 10.0.0.1')
    parser.add_argument('-p', '--port', help='specify port to be scanned (80 443 22...). ex: gping.py -t 10.0.0.1 -p 443', nargs='*', type=int)                 
    parser.add_argument('-o', '--output', help='output results to a file of your choice')
    args = parser.parse_args()

    def arp_scan():
        conf.verb=0
        ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=args.arp), timeout=2)
        print(ans)
        print(unans)
        for snd,rcv in ans:
            oui = OuiLookup().query(rcv.sprintf(r"%Ether.src%"))
            for n in oui:
                for i in n:
                    print(rcv.sprintf(r"MAC: %Ether.src% - ip: %ARP.psrc%") + " - " + n[i])
        if args.output:
            with open(args.output, 'w') as o:
                for snd,rcv in ans:
                    o.writelines(rcv.sprintf(r"MAC: %Ether.src% - ip: %ARP.psrc%") + " - " + n[i])

    def tcp_scan(ip, port):
        start_clock = datetime.now()
        try:
            ping = sr1(IP(dst=ip)/ICMP(), timeout=3)
            if ping == None:
                print("\n[*] Target did not respond to ICMP, Beginning Scan...")
            else:
                print("\n[*] Target is Up, Beginning Scan...")
        except Exception:
            print("\n[!] Couldn't Resolve Target")
            stop_clock = datetime.now()
            total_time = stop_clock - start_clock
            print("[*] Scanning Finished!")
            print("[*] Total Scan Duration: " + str(total_time))
            print("[!] Exiting...")
            sys.exit(1)
        src_port = random.randint(1025,65535)
        print("[*] Scanning: " + args.tcp +':' + str(args.port)+'\n')
        ans = sr1(IP(dst=ip)/TCP(sport=src_port, dport=port, flags='S'), timeout=2, verbose=False)
        if ans == None:
            print("[!] Port:"+ str(args.port)+ ' not open')
            stop_clock = datetime.now()
            total_time = stop_clock - start_clock
            print("\n[*] Scanning Finished!")
            print("[*] Total Scan Duration: " + str(total_time))
            print("[!] Exiting...")
            sys.exit(1)
        else:
            for rcv in ans:
                print('[*] '+rcv.sprintf(r"ip: %IP.src% - Port: %TCP.sport% - Flag: %TCP.flags%"))
                tcprst = sr(IP(dst=ip)/TCP(sport=src_port, dport=port, flags='R'), timeout=2, verbose=False)
        if args.output:
            with open(args.output, 'w') as o:
                o.writelines((rcv.sprintf(r"ip: %IP.src% - Port: %TCP.sport% - Flag: %TCP.flags%")))
        stop_clock = datetime.now()
        total_time = stop_clock - start_clock
        print("\n[*] Scanning Finished!")
        print("[*] Total Scan Duration: " + str(total_time))

    if args.port:
        port = args.port
    else:
        port = range(1, 1024)

    if args.tcp:
        tcp_scan(str(args.tcp), port)

    if args.arp:
        arp_scan()

if __name__=='__main__':
    BANNER()
    main()
