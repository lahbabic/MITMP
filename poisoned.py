#!/usr/bin/env python
# -*- coding: utf-8 -*-

import subprocess, sys
from optparse import OptionParser
from scapy.all import *

W = '\033[0m'   # white
R = '\033[31m'  # red
G = '\033[32m'  # green

def print_ok():
    print(W+"["+G+"ok"+W+"]")

def print_err():
    print(W+"["+R+"error"+W+"]")


def run_command(*args, **kwargs):
	"Run a command and return stdout or stderr"
	print("Running command: ", end = "")
	print(' '.join(args), end=" ")
	try:
		res = subprocess.check_output(args, stderr=subprocess.STDOUT)
	except subprocess.CalledProcessError:
		print_err()
		return None
	print_ok()
	return res


def parse_arp_entry(entry):
	try:
		entry = entry.decode("utf-8")
		ip = (entry.split('('))[1].split(')')[0]
		mac = (entry.split('at '))[1].split(' on')[0]
		return (ip, mac)
	except:
		return None

def neigh(iface):
	"Return list of tuples (ipv4, mac@) of neighbors machines in mac table"
	neighbor = []
	result = run_command("arp", "-i", iface, "-a")
	if not result:
		return None

	res = result.split(b'?')
	if len(res):
		res.pop(0)

	try:
		for r in res:
			if b"permanent" not in r:
				neighbor.append( parse_arp_entry(r) )
		if neighbor:
			return neighbor
		else: return None
	except:
		return None



def check_for_inet(iter):
	"Return True if their is an ipv4 address in the iterable"
	for line in iter:
		addr_type = line.split(" ")[0]
		if addr_type == 'inet':
			return True
	print("Interface doesn't have an IPv4 assigned")
	return False


def get_my_ip_mac(iface):
	"Return tuple (ipv4, mac@) if exists, None otherwise"
	res = run_command("ip", "a", "show", "dev", iface)
	if not res:
		return None

	res = res.decode("utf-8").split('\n\t')
	inet = (check_for_inet(res) == True)
	if not inet:
		return None

	ip, mac = "", ""
	for r in res:
		entry = r.split(" ")
		if entry[0] == 'inet':
			ip = (entry[1].split('/'))[0]
		elif entry[0] == 'ether':
			mac = entry[1]

	return (ip, mac)




def build_arp_packet( iface, my_ip_mac, neighbors ):

    if len( neighbors ) <= 1:
        print("There are no enough neighbors to be sure")
    answer = False
    # set verbosity to None
    conf.verb = 0
    for ip, mac in neighbors:
        eth = Ether( src=my_ip_mac[1], dst=mac )
        arp = ARP( pdst=my_ip_mac[0] )
        pckt = eth/arp
        try:
            ans , unans = srp( pckt , timeout = 2 )
            ans = ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc%") )
            if ans:
                answer = True
                print( "Answer from "+ ip +" : \n\t" + ans )
        except:
            pass
    if not answer:
        print("No reply has been received.")
    return 0


def main( ):

    option_parser = OptionParser()
    option_parser.add_option("-i", "--intf", dest="iface",
                      help="network interface to use")

    (options, args) = option_parser.parse_args()
    if options.iface is None:
        print("Missing argument.")
        print("Please use -h for more information.")
        print("\t"+sys.argv[0]+ " -h")
        exit("\n")

    neighbor = []
    my_ip_mac = []
    print("\n")
    my_ip_mac = get_my_ip_mac( options.iface )
    if not my_ip_mac:
        exit(0)

    print("My ip is: "+my_ip_mac[0])
    print("My mac address is: "+my_ip_mac[1])

    neighbor = neigh( options.iface )
    if not neighbor:
        print("No neighbor found")
        exit(0)
    build_arp_packet( iface, my_ip_mac, neighbor )


if __name__ == '__main__':
	main( )
