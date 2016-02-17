#!/usr/bin/env python

import sys
import netifaces
import binascii
import StringIO
import hashlib
import random
import re
from socket import *
from struct import *
from select import select

MACTELNET_PORT = 20561
MACTELNET_CLIENT_TYPE = 0x0015
MACTELNET_CPMAGIC = 0x563412ff

MT_HEADER_LEN = 22
MT_CPHEADER_LEN = 9

MT_PTYPE_SESSIONSTART = 0
MT_PTYPE_DATA = 1
MT_PTYPE_ACK = 2
MT_PTYPE_PING = 4
MT_PTYPE_PONG = 5
MT_PTYPE_END = 255

MT_CPTYPE_BEGINAUTH = 0
MT_CPTYPE_ENCRYPTIONKEY = 1
MT_CPTYPE_PASSWORD = 2
MT_CPTYPE_USERNAME = 3
MT_CPTYPE_TERM_TYPE = 4
MT_CPTYPE_TERM_WIDTH = 5
MT_CPTYPE_TERM_HEIGHT = 6
MT_CPTYPE_PACKET_ERROR = 7
MT_CPTYPE_END_AUTH = 9

class Message(object):
    def __init__(self, type=None, src_mac=None, dst_mac=None, session_key=None, counter=None):
        self.cpackets = []
        self.plain_data = None
        self.version = 1
        self.type = type
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.session_key = session_key
        self.counter = counter

        if src_mac:
            self.src_mac_raw = parse_mac(src_mac)
        if dst_mac:
            self.dst_mac_raw = parse_mac(dst_mac)

    def add_control(self, cptype, cpdata):
        self.cpackets.append((cptype, cpdata))

    def add_plain(self, data):
        self.plain_data = data

    def get_buffer(self):
        buf = StringIO.StringIO()

        # version
        buf.write(pack('B', self.version))

        buf.write(pack('B', self.type))
        buf.write(self.src_mac_raw)
        buf.write(self.dst_mac_raw)
        buf.write(pack('!H', self.session_key))

        buf.write(pack('!H', MACTELNET_CLIENT_TYPE))

        buf.write(pack('!I', self.counter))

        for cptype, cpdata in self.cpackets:
            buf.write(pack('!IB', MACTELNET_CPMAGIC, cptype))
            if cpdata is None:
                buf.write(pack('!I', 0))
            else:
                buf.write(pack('!I', len(cpdata)))
                buf.write(cpdata)

        if not self.plain_data is None:
            buf.write(self.plain_data)
        return buf.getvalue()

    def parse(self, data):
        self.version, self.type, self.src_mac_raw, self.dst_mac_raw, self.client_type, \
            self.session_key, self.counter = unpack_from('!BB6s6sHHI', data, 0)
        self.src_mac = mac_to_str(self.src_mac_raw)
        self.dst_mac = mac_to_str(self.dst_mac_raw)
        pos = MT_HEADER_LEN
        while pos < len(data):
            is_plain = True
            plain_pos = pos
            if pos + MT_CPHEADER_LEN <= len(data):
                magic, cptype, cpdatalen = unpack_from('!IBI', data, pos)
                if magic == MACTELNET_CPMAGIC:
                    pos += MT_CPHEADER_LEN
                    if len(data) >= pos + cpdatalen:
                        cpdata = data[pos:pos+cpdatalen]
                        self.cpackets.append((cptype, cpdata))
                        pos += cpdatalen
                        is_plain = False
            if is_plain:
                self.plain_data = data[plain_pos:]
                break

    def __str__(self):
        res = "version: %(version)d, type: %(type)d, src: %(src_mac)s, dst: %(dst_mac)s," \
            " session_key: 0x%(session_key)04x, counter:%(counter)d" \
        % self.__dict__
        for cptype, cpdata in self.cpackets:
            if cpdata is None:
                cpdata = ''
            res += "\n cptype: %d, datalen: %d" % (cptype, len(cpdata))
            res += "\n  data:" + binascii.hexlify(cpdata)
        if not self.plain_data is None:
            res += "\n  plain_data hex:" + binascii.hexlify(self.plain_data)
            res += "\n  plain_data:" + self.plain_data
        return res

def parse_msg(msg, session_key):
    parsed = Message()
    parsed.parse(msg)
    if parsed.version != 1 or parsed.session_key != session_key or parsed.client_type != MACTELNET_CLIENT_TYPE:
        return None
    return parsed

def parse_mac(mac_str):
    return binascii.unhexlify(mac_str.replace(':',''))

def mac_to_str(mac):
    return "%02x:%02x:%02x:%02x:%02x:%02x" % tuple(ord(x) for x in mac)

class Connection(object):
    def __init__(self, dst_mac):
        self.incounter = -1
        self.outcounter = 0
        self.session_key = random.randint(0, 0xffff)
        self.insock = socket(AF_INET, SOCK_DGRAM)
        self.insock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.insock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        self.insock.bind(('', 0))
        _, self.inport = self.insock.getsockname()
        #print "Local port:", self.inport

        self.dst_mac = dst_mac
        if not self.find_interface():
            print "Error: can't find interface to use for connection"
            sys.exit(1)


    def find_interface(self):
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
            testsock.bind((src_ip, self.inport))

            msg = Message(MT_PTYPE_SESSIONSTART, src_mac, self.dst_mac, self.session_key, 0)
            testsock.sendto(msg.get_buffer(), ('255.255.255.255', MACTELNET_PORT))

            inlist, _, _ = select((self.insock,), (), (), 2)
            if len(inlist) > 0:
                self.outsock = testsock
                self.src_mac = src_mac
                self.src_ip = src_ip
                return True
            testsock.close()

        return False

    def get_reply(self):
        while True:
            data = self.insock.recv(1500)
            #print "Recv:", len(data), binascii.hexlify(data)
            reply = parse_msg(data, self.session_key)
            #print " parsed:", reply
            if reply:
                if reply.type == MT_PTYPE_DATA:
                    # send ack
                    msg = Message(MT_PTYPE_ACK, reply.dst_mac, reply.src_mac, self.session_key, reply.counter + len(data) - MT_HEADER_LEN)
                    msg_data = msg.get_buffer()
                    self.outsock.sendto(msg_data, ('255.255.255.255', MACTELNET_PORT))
                    if reply.counter > self.incounter or self.incounter - reply.counter > 65535:
                        self.incounter = reply.counter
                    else:
                        continue
            return reply

    def send_msg(self, msg, need_ack=True):
        #print "Sending:", msg
        msg_data = msg.get_buffer()
        self.outsock.sendto(msg_data, ('255.255.255.255', MACTELNET_PORT))
        if need_ack:
            ack = self.get_reply()
        self.outcounter += len(msg_data) - MT_HEADER_LEN

    def new_message(self, type):
        return Message(type, self.src_mac, self.dst_mac, self.session_key, self.outcounter)

def clean_esc(s):
    s = re.sub('\x1b\\[\\d+[ABCD]', '', s)
    s = re.sub('\x1b[DZ]', '', s)
    s = re.sub('\x1b\\[6n', '', s)
    s = re.sub('\x1b\\[H', '', s)
    s = re.sub('\x1b\\[\\d*m', '', s)
    s = re.sub('\x1b\\[[?0-9]*[lh]', '', s)
    s = re.sub('\x1b\\[[;0-9]*r', '', s)
    s = re.sub('\x1b', '<ESC>', s)
    return s

def main():
    if len(sys.argv) < 2:
        print "MAC address needed"
        sys.exit(-1)
    dst_mac = sys.argv[1]
    print "Connecting to MAC:", dst_mac

    random.seed()

    user = "admin"
    passwd = ""


    conn = Connection(dst_mac)

    # ACK for session start
    reply = conn.get_reply()
    # print "ACK:", reply

    # authentication
    msg = conn.new_message(MT_PTYPE_DATA)
    msg.add_control(MT_CPTYPE_BEGINAUTH, None)
    conn.send_msg(msg)

    reply = conn.get_reply()
    #print "Reply:", reply
    enc_key = ''
    if reply.type == MT_PTYPE_DATA:
        for cptype, cpdata in reply.cpackets:
            if cptype == MT_CPTYPE_ENCRYPTIONKEY:
                enc_key = cpdata

    msg = conn.new_message(MT_PTYPE_DATA)
    passwd_hash = '\x00' + hashlib.md5('\x00' + passwd + enc_key).digest()
    msg.add_control(MT_CPTYPE_PASSWORD, passwd_hash)
    msg.add_control(MT_CPTYPE_USERNAME, user)
    msg.add_control(MT_CPTYPE_TERM_TYPE, 'ansi')
    msg.add_control(MT_CPTYPE_TERM_WIDTH, pack('!H', 80))
    msg.add_control(MT_CPTYPE_TERM_HEIGHT, pack('!H', 25))
    conn.send_msg(msg)
    reply = conn.get_reply()
    #print "Reply:", reply

    commands = [
        '/system identity print\r'
    ]

    while True:
        reply = conn.get_reply()
        #print "\nReply:", reply
        if reply.plain_data:
            print "\n" + binascii.hexlify(reply.plain_data)
            sys.stdout.write('<<\n' + reply.plain_data.replace('\x1b', '<ESC>') + '\n>>\n\n')
            sys.stdout.write(clean_esc(reply.plain_data))
            sys.stdout.flush()
            if reply.plain_data.count('\x1b[6n') > 0:
                # asking for cursor pos, give some reply
                msg = conn.new_message(MT_PTYPE_DATA)
                msg.add_plain('\x1b[1;80R' * reply.plain_data.count('\x1b[6n'))
                conn.send_msg(msg)
            if reply.plain_data.endswith('> ') and len(commands):
                msg = conn.new_message(MT_PTYPE_DATA)
                msg.add_plain(commands.pop(0))
                conn.send_msg(msg)

        if reply.type == MT_PTYPE_END:
            break



if __name__ == "__main__":
    main()
