import socket
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import argparse
from OuiLookup import OuiLookup

def main():        
    parser = argparse.ArgumentParser(description='A simple command line ARP/TCP scanning tool. Use -a to perform an ARP scan on a given subnet. Use -t to perform a TCP SYN scan, ' 
                                                'if no ports are selected then ports 1-1024 will be scanned. Use -p to specify ports. Please see the arguments for examples.')
    parser.add_argument('-a', '--arp', help='perform an arp-scan on the provided subnet or IP which will return MAC, IP, and OUI lookup. ex: gping.py -a 10.0.0.1 or gping.py -a 10.0.0.0/24')
    parser.add_argument('-t', '--tcp', help='perform a tcp-scan on the provided subnet. ex: gping.py -t 10.0.0.1')
    parser.add_argument('-p', '--ports', help='specify ports to be scanned (80 443 22...). ex: gping.py -t 10.0.0.1 -p 443', nargs='*', type=int)                 
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
                    print(rcv.sprintf(r"MAC: %Ether.src% - Host: %ARP.psrc%") + " - " + n[i])
        if args.output:
            with open(args.output, 'w') as o:
                for snd,rcv in ans:
                    o.writelines(rcv.sprintf(r"MAC: %Ether.src% - Host: %ARP.psrc%") + "\n")

    def tcp_scan(ip, ports):
        print("Scanning: " + args.tcp)
        try:
            ans,unans = sr(IP(dst=ip)/TCP(sport=RandShort(), dport=ports, flags='S'), timeout=2, retry=1, verbose=False)
            print(ans)
            print(unans)
        except socket.gaierror:
            raise ValueError('Hostname {} could not be resolved.'.format(ip))
        for snd,rcv in ans:
            print(rcv.sprintf(r"Host: %IP.src% - Port: %TCP.sport% - Flag: %TCP.flags%"))
        if args.output:
            with open(args.output, 'w') as o:
                o.writelines((rcv.sprintf(r"Host: %IP.src% - Port: %TCP.sport% - Flag: %TCP.flags%")))
            print("scan is complete")

    if args.ports:
        ports = args.ports
    else:
        ports = range(1, 1024)
    if args.arp:
        arp_scan()
    if args.tcp:
        tcp_scan(str(args.tcp), ports)

if __name__=='__main__':
        main()
