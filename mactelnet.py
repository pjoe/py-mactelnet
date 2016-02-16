#!/usr/bin/env python

import sys
import netifaces
import binascii
import StringIO
from socket import *
from struct import *
from select import select

def make_msg(type, src_mac, dst_mac, session_key, counter):
    buf = StringIO.StringIO()

    # version
    buf.write(pack('B', 1))

    buf.write(pack('B', type))
    buf.write(parse_mac(src_mac))
    buf.write(parse_mac(dst_mac))
    buf.write(pack('!H', session_key))

    # mactelnet client type
    buf.write(pack('!H', 0x0015))

    buf.write(pack('!I', counter))
    return buf.getvalue()

def parse_mac(mac_str):
    return binascii.unhexlify(mac_str.replace(':',''))

def find_interface(dst_mac, insock, inport):
    for iface in netifaces.interfaces():
        if iface.startswith('lo'):
            continue
        addrs = netifaces.ifaddresses(iface)
        if not addrs.has_key(netifaces.AF_INET):
            continue
        src_mac = addrs[netifaces.AF_LINK][0]['addr']
        src_ip = addrs[netifaces.AF_INET][0]['addr']
        if not src_mac or not src_ip:
            continue
        print "Trying if:", iface, src_ip, src_mac
        testsock = socket(AF_INET, SOCK_DGRAM)
        testsock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        testsock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        testsock.bind((src_ip, inport))

        msg = make_msg(0, src_mac, dst_mac, 0x5432, 0)
        print "MSG:", binascii.hexlify(msg)
        testsock.sendto(msg, ('255.255.255.255', 20561))

        inlist, _, _ = select((insock,), (), (), 2)
        if len(inlist) > 0:
            return (src_mac, src_ip)
        testsock.close()

    return (None, None)


def main():
    if len(sys.argv) < 2:
        print "MAC address needed"
        sys.exit(-1)
    dst_mac = sys.argv[1]
    print "Connecting to MAC:", dst_mac

    inport = 1888
    insock = socket(AF_INET, SOCK_DGRAM)
    insock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    insock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
    insock.bind(('', inport))

    src_mac, src_ip = find_interface(dst_mac, insock, inport)
    print "Using:", src_mac, src_ip
    reply = insock.recv(1500)
    print "Reply:", len(reply), binascii.hexlify(reply)

if __name__ == "__main__":
    main()
