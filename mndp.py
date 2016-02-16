#!/usr/bin/env python

from socket import *
from struct import *
from binascii import hexlify
import sys

def parse_mndp(data):
    entry = {}
    names = ('version', 'ttl', 'checksum')
    for idx, val in enumerate(unpack_from('!BBH', data)):
        entry[names[idx]] = val

    pos = 4
    while pos + 4 < len(data):
        type, length = unpack_from('!HH', data, pos)
        pos += 4

        # MAC
        if type == 1:
            (mac,) = unpack_from('6s', data, pos)
            entry['mac'] = "%02x:%02x:%02x:%02x:%02x:%02x" % tuple(ord(x) for x in mac)

        # Identity
        elif type == 5:
            entry['id'] = data[pos:pos + length]

        # Platform
        elif type == 8:
            entry['platform'] = data[pos:pos + length]

        # Version
        elif type == 7:
            entry['version'] = data[pos:pos + length]

        # uptime?
        elif type == 10:
            (uptime,) = unpack_from('<I', data, pos)
            entry['uptime'] = uptime

        # hardware
        elif type == 12:
            entry['hardware'] = data[pos:pos + length]

        # softid
        elif type == 11:
            entry['softid'] = data[pos:pos + length]

        # ifname
        elif type == 16:
            entry['ifname'] = data[pos:pos + length]

        else:
            entry['unknown-%d' % type] = hexlify(data[pos:pos + length])

        pos += length

    return entry

def mndp_scan():
    cs = socket(AF_INET, SOCK_DGRAM)

    cs.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    cs.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
    cs.bind(('', 5678))

    cs.sendto('\0\0\0\0', ('255.255.255.255', 5678))

    try:
        entries = {}
        while True:
            (data, src_addr) = cs.recvfrom(1500)
            # ignore the msg we getourselves
            if data == '\0\0\0\0':
                continue

            if len(data) < 18:
                continue
            entry = parse_mndp(data)
            if not entries.has_key(entry['mac']):
                print "Reply from:", src_addr, len(data)
                print " %(mac)s, ID: %(id)s" % entry
                print "  Ver: %(version)s, HW: %(hardware)s, Uptime: %(uptime)d" % entry
                print "  SoftID: %(softid)s, IF: %(ifname)s, Platform: %(platform)s" % entry
                entries[entry['mac']] = entry



    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    mndp_scan()
