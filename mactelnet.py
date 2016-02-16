#!/usr/bin/env python

import sys
import netifaces
import binascii
import StringIO
from socket import *
from struct import *
from select import select

MACTELNET_PORT = 20561

def init_msg(type, src_mac, dst_mac, session_key, counter):
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
    return buf

def parse_msg(msg, session_key):
    version, type, src_mac, dst_mac, client_type, msg_session_key, counter = unpack_from('!BB6s6sHHI', msg, 0)
    if version != 1 or msg_session_key != session_key or client_type != 0x0015:
        return None
    return (type, mac_to_str(src_mac), mac_to_str(dst_mac), counter)


def send_msg(sock, msg):
    pass

def parse_mac(mac_str):
    return binascii.unhexlify(mac_str.replace(':',''))

def mac_to_str(mac):
    return "%02x:%02x:%02x:%02x:%02x:%02x" % tuple(ord(x) for x in mac)

def find_interface(dst_mac, insock, inport, session_key):
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

        msg = init_msg(0, src_mac, dst_mac, session_key, 0).getvalue()
        print "MSG:", binascii.hexlify(msg)
        testsock.sendto(msg, ('255.255.255.255', MACTELNET_PORT))

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

    session_key = 0x6785
    inport = 1888
    insock = socket(AF_INET, SOCK_DGRAM)
    insock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    insock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
    insock.bind(('', inport))

    src_mac, src_ip = find_interface(dst_mac, insock, inport, session_key)
    print "Using:", src_mac, src_ip
    reply = insock.recv(1500)
    print "Reply:", len(reply), binascii.hexlify(reply)
    type, src_mac, dst_mac, counter = parse_msg(reply, session_key)
    print " type: %d, src: %s, dst: %s, counter: %d" % (type, src_mac, dst_mac, counter)

if __name__ == "__main__":
    main()
