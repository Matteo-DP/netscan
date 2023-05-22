import scapy.config
import netaddr
import scapy.layers.l2
import scapy.route
import socket
import os
import sys
import logging
import math
import errno
import argparse
import json

interface_to_scan = "wlp1s0"
dbPath = "default"

parser = argparse.ArgumentParser(description='Network scanning tool')
parser.add_argument('--db', type=str, help='Specify database file')
parser.add_argument('-ns', '--no-save', help="Don't save to database", action="store_true")

args = parser.parse_args()

logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logger = logging.getLogger(__name__)



def main():
    if os.geteuid() != 0:
        print('You need to be root to run this script', file=sys.stderr)
        sys.exit(1)

    for network, netmask, _, interface, address, _ in scapy.config.conf.route.routes:
        
        if interface_to_scan and interface_to_scan != interface:
            continue

        # skip loopback network and default gw
        if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0':
            continue

        if netmask <= 0 or netmask == 0xFFFFFFFF:
            continue

        # skip docker interface
        if interface != interface_to_scan \
                and (interface.startswith('docker')
                     or interface.startswith('br-')
                     or interface.startswith('tun')):
            logger.warning("Skipping interface '%s'" % interface)
            continue

        net = to_CIDR_notation(network, netmask)

        if net:
            scan_and_print_neighbors(net, interface)


# TODO: understand this
def to_CIDR_notation(bytes_network, bytes_netmask):
    network = scapy.utils.ltoa(bytes_network)
    netmask = long2net(bytes_netmask)
    net = "%s/%s" % (network, netmask)
    if netmask < 16:
        logger.warning("%s is too big. skipping" % net)
        return None

    return net

# TODO: understand this
def long2net(arg):
    if (arg <= 0 or arg >= 0xFFFFFFFF):
        raise ValueError("illegal netmask value", hex(arg))
    return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))


def scan_and_print_neighbors(net, interface, timeout=5):
    
    data = {
        "endpoints": []
    }
    
    logger.info("arping %s on %s" % (net, interface))
    try:
        ans, unans = scapy.layers.l2.arping(net, iface=interface, timeout=timeout, verbose=True)
        logger.info("Received %d responses" % len(ans.res))
        logger.info("-------------------------------------------------")
        for s, r in ans.res:
            line = r.sprintf("%Ether.src%  %ARP.psrc%")
            hostname = ""
            try:
                hostname = socket.gethostbyaddr(r.psrc)
                hostname = hostname[0]
                line += " " + hostname
            except socket.herror:
                # failed to resolve
                pass
            vendor = ""
            try:
                vendor = netaddr.EUI(r.hwsrc).oui.registration().org
                line += " (%s)" % vendor
            except netaddr.NotRegisteredError:
                pass
            data["endpoints"].append({
                "ipv4": r.psrc,
                "mac": r.hwsrc,
                "hostname": hostname,
                "vendor": vendor
            })
            logger.info(line)
    except socket.error as e:
        if e.errno == errno.EPERM:      # Operation not permitted
            logger.error("%s. Did you run as root?", e.strerror)
        else:
            raise
        
    logger.info("-------------------------------------------------")
    savetoDB(data)
    
def savetoDB(data):
    if args.no_save:
        logger.info("Not saving to DB")
        return
    with open(f"db/{dbPath}.json", "w") as f:
        f.write(json.dumps(data, indent=4))
    logger.info("Saved to DB: %s.json" % dbPath)

def parseArgs():
    global dbPath
    if args.db:
        dbPath = args.db
    if args.no_save:
        logger.info("Not using any database")
    else:
        logger.info("Using database: %s.json" % dbPath)
    main()
        
parseArgs() # Begin