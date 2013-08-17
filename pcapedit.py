#!/usr/bin/env python

import os, sys, re, binascii

from cmd2 import Cmd
from datetime import datetime

import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *
from scapy.utils import *

class editor(Cmd):

    intro = 'PcapEdit - An Interactive Pcap Editor\n'
    prompt = '>>> '

    packets = []
    editid = -1
    inpcap = None
    outpcap = None
    customipchksum = False
    customtcpchksum = False
    customudpchksum = False

    def help_analyze(self):
        print 'USAGE: analyze <pcapfile>'
        print 'Analyze packets from <pcapfile>'

    def do_analyze(self, line):
        if line != '':
            if os.path.isfile(line):
                self.inpcap = line
                self.packets = rdpcap(self.inpcap)
                print 'Read %d packets from %s' % (len(self.packets), self.inpcap)
            else:
                print '%s doesn\'t exist!' % (line)
        else:
            self.help_analyze()

    def help_ls(self):
        print 'USAGE: ls [packetid]'
        print 'Show ls for packetid'
        print 'If no packetid is passed, use editid instead'

    def do_ls(self, line):
        if self.packets and len(self.packets) > 0:
            if line != '':
                id = int(line)
                if id >= 0 and id <= (len(self.packets) - 1):
                    print ls(self.packets[id])
                else:
                    print 'Packet %d not found! Available %d - %d' % (
                            id,
                            0,
                            (len(self.packets) - 1))
            elif self.editid != -1:
                print ls(self.packets[self.editid])
            else:
                print 'No packetid to ls! Pass one as argument or use \'edit\' first.'
                self.help_ls()
        else:
            print 'Nothing to ls! Use \'analyze\' first.'

    def help_summary(self):
        print 'USAGE: summary [packetid]'
        print 'Show summary for packetid'
        print 'If no packetid is passed, use editid instead'

    def do_summary(self, line):
        if self.packets and len(self.packets) > 0:
            if line != '':
                id = int(line)
                if id < 0 or id > (len(self.packets) - 1):
                    id = -1
            elif self.editid != -1:
                id = self.editid
            else:
                id = -1

            count = 0
            for packet in self.packets:
                if id != -1 and count != id:
                    count += 1
                    continue

                ptime = datetime.fromtimestamp(packet.time).strftime('%Y/%m/%d %H:%M:%S')
                data = None
                if packet.haslayer(IP):
                    sip = packet.getlayer(IP).src
                    dip = packet.getlayer(IP).dst

                    if packet.haslayer(TCP):
                        l4proto = 'TCP'
                        sport = packet.getlayer(TCP).sport
                        dport = packet.getlayer(TCP).dport
                        flags = packet.getlayer(TCP).flags

                    elif packet.haslayer(UDP):
                        l4proto = 'UDP'
                        sport = packet.getlayer(UDP).sport
                        dport = packet.getlayer(UDP).dport

                    if Raw in packet:
                        data = packet[Raw]
                    else:
                        data = ''

                    if l4proto == 'TCP':
                        flaglist = []
                        if flags & 1: flaglist.append('F')
                        if flags & 2: flaglist.append('S')
                        if flags & 4: flaglist.append('R')
                        if flags & 8: flaglist.append('P')
                        if flags & 16: flaglist.append('A')
                        if flags & 32: flaglist.append('U')
                        if flags & 64: flaglist.append('E')
                        if flags & 128: flaglist.append('C')
                        if flags & 256: flaglist.append('N')
                        flagstr = ''.join(flaglist)

                        if len(data) > 0:
                            summary = '%s (%d bytes)' % (flagstr, len(data))
                        else:
                            summary = '%s' % (flagstr)
                    elif l4proto == 'UDP':
                        if len(data) > 0:
                            summary = '(%d bytes)' % (len(data))
                        else:
                            summary = '(%d bytes)' % (len(packet[3]))

                    print '%6d: %-15s %23s -> %-21s %3s %s' % (
                            count,
                            ptime,
                            '%s:%s' % (sip, sport),
                            '%s:%s' % (dip, dport),
                            l4proto,
                            summary)

                count += 1
        else:
            print 'Nothing to summarize! Use \'analyze\' first.'

    def help_hexdump(self):
        print 'USAGE: hexdump [packetid]'
        print 'Show hexdump for packetid'
        print 'If no packetid is passed, use editid instead'

    def do_hexdump(self, line):
        if self.packets and len(self.packets) > 0:
            if line != '':
                id = int(line)
                if id >= 0 and id <= (len(self.packets) - 1):
                    print hexdump(self.packets[id])
                else:
                    print 'Packet %d not found! Available %d - %d' % (
                            id,
                            0,
                            (len(self.packets) - 1))
            elif self.editid != -1:
                print hexdump(self.packets[self.editid])
            else:
                print 'No packetid to hexdump! Pass one as argument or use \'edit\' first.'
                self.help_hexdump()
        else:
            print 'Nothing to hexdump! Use \'analyze\' first.'

    def help_pdfdump(self):
        print 'USAGE: pdfdump [packetid]'
        print 'Dump packetid to a PDF'
        print 'If no packetid is passed, use editid instead'

    def do_pdfdump(self, line):
        if self.packets and len(self.packets) > 0:
            if line != '':
                id = int(line)
                if id >= 0 and id <= (len(self.packets) - 1):
                    print self.packets[id].pdfdump()
                else:
                    print 'Packet %d not found! Available %d - %d' % (
                            id,
                            0,
                            (len(self.packets) - 1))
            elif self.editid != -1:
                print self.packets[self.editid].pdfdump()
            else:
                print 'No packetid to dump! Pass one as argument or use \'edit\' first.'
                self.help_pdfdump()
        else:
            print 'Nothing to dump! Use \'analyze\' first.'

    def help_scapycmd(self):
        print 'USAGE: scapycmd [packetid]'
        print 'Show Scapy command to generate packetid'
        print 'If no packetid is passed, use editid instead'

    def do_scapycmd(self, line):
        if self.packets and len(self.packets) > 0:
            if line != '':
                id = int(line)
                if id >= 0 and id <= (len(self.packets) - 1):
                    print self.packets[id].command()
                else:
                    print 'Packet %d not found! Available %d - %d' % (
                            id,
                            0,
                            (len(self.packets) - 1))
            elif self.editid != -1:
                print self.packets[self.editid].command()
            else:
                print 'No packetid to show as Scapy command! Pass one as argument or use \'edit\' first.'
                self.help_scapycmd()
        else:
            print 'Nothing to show as Scapy command! Use \'analyze\' first.'

    def help_wireshark(self):
        print 'USAGE: wireshark [packetid]'
        print 'Show packetid in Wireshark'
        print 'If no packetid is passed, use editid instead'

    def do_wireshark(self, line):
        if self.packets and len(self.packets) > 0:
            if line != '':
                id = int(line)
                if id >= 0 and id <= (len(self.packets) - 1):
                    wireshark(self.packets[id])
                else:
                    print 'Packet %d not found! Available %d - %d' % (
                            id,
                            0,
                            (len(self.packets) - 1))
            elif self.editid != -1:
                print wireshark(self.packets[self.editid])
            else:
                print 'No packetid to show in wireshark! Pass one as argument or use \'edit\' first.'
                self.help_wireshark()
        else:
            print 'Nothing to show in wireshark! Use \'analyze\' first.'

    def help_edit(self):
        print 'USAGE: edit [packetid]'
        print 'Use <packetid> for further analysis/editing operations'
        print 'To stop editing, use edit without arguments'

    def do_edit(self, line):
        if self.packets and len(self.packets) > 0:
            if line != '':
                id = int(line)
                if id >= 0 and id <= (len(self.packets) - 1):
                    self.editid = id
                    print 'Editing packet id: %d' % (self.editid)
                    self.do_summary(line)
                else:
                    print 'Packet %d not found! Available %d - %d' % (
                            id,
                            0,
                            (len(self.packets) - 1))
            else:
                self.editid = -1
        else:
            print 'Nothing to edit! Use \'analyze\' first.'

    def help_set(self):
        print 'USAGE: set <key> <value>'
        print 'Where key: (ether|ip|tcp|udp|dns).field'
        print 'Valid fields are listed in \'ls\''

    def do_set(self, line):
        if self.packets and len(self.packets) > 0:
            if line != '':
                if self.editid != -1:
                    editkey = line.split()[0]
                    editproto = editkey.split('.')[0]
                    editfield = editkey.split('.')[1]
                    editvalue = line.split()[1]

                    if re.search(r'(?i)^ether$', editproto):
                        editproto = 'Ether'
                        if self.packets[self.editid].haslayer(editproto):
                            if re.search(r'(?i)^src$', editfield):
                                oldeditvalue = self.packets[self.editid][Ether].src
                                self.packets[self.editid].getlayer(Ether).src = str(editvalue)
                                print '%6d: Ether.src: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(Ether).src)
                            elif re.search(r'(?i)^dst$', editfield):
                                oldeditvalue = self.packets[self.editid][Ether].dst
                                self.packets[self.editid].getlayer(Ether).dst = str(editvalue)
                                print '%6d: Ether.dst: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(Ether).dst)
                            elif re.search(r'(?i)^type$', editfield):
                                oldeditvalue = self.packets[self.editid][Ether].type
                                self.packets[self.editid].getlayer(Ether).type = int(editvalue)
                                print '%6d: Ether.type: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(Ether).type)
                            else:
                                print 'Could not find \'Ether.%s\' in packet %d' % (editfield, self.editid)

                    elif re.search(r'(?i)^ip$', editproto):
                        editproto = 'IP'
                        if self.packets[self.editid].haslayer(editproto):
                            if re.search(r'(?i)^version$', editfield):
                                oldeditvalue = self.packets[self.editid][IP].version
                                self.packets[self.editid].getlayer(IP).version = int(editvalue)
                                print '%6d: IP.version: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(IP).version)
                            elif re.search(r'(?i)^ihl$', editfield):
                                oldeditvalue = self.packets[self.editid][IP].ihl
                                self.packets[self.editid].getlayer(IP).ihl = int(editvalue)
                                print '%6d: IP.ihl: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(IP).ihl)
                            elif re.search(r'(?i)^tos$', editfield):
                                oldeditvalue = self.packets[self.editid][IP].tos
                                self.packets[self.editid].getlayer(IP).tos = int(editvalue)
                                print '%6d: IP.tos: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(IP).tos)
                            elif re.search(r'(?i)^len$', editfield):
                                oldeditvalue = self.packets[self.editid][IP].len
                                self.packets[self.editid].getlayer(IP).len = int(editvalue)
                                print '%6d: IP.len: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(IP).len)
                            elif re.search(r'(?i)^id$', editfield):
                                oldeditvalue = self.packets[self.editid][IP].id
                                self.packets[self.editid].getlayer(IP).id = int(editvalue)
                                print '%6d: IP.id: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(IP).id)
                            elif re.search(r'(?i)^flags$', editfield):
                                oldeditvalue = self.packets[self.editid][IP].flags
                                self.packets[self.editid].getlayer(IP).flags = int(editvalue)
                                print '%6d: IP.flags: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(IP).flags)
                            elif re.search(r'(?i)^frag$', editfield):
                                oldeditvalue = self.packets[self.editid][IP].frag
                                self.packets[self.editid].getlayer(IP).frag = int(editvalue)
                                print '%6d: IP.frag: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(IP).frag)
                            elif re.search(r'(?i)^ttl$', editfield):
                                oldeditvalue = self.packets[self.editid][IP].ttl
                                self.packets[self.editid].getlayer(IP).ttl = int(editvalue)
                                print '%6d: IP.ttl: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(IP).ttl)
                            elif re.search(r'(?i)^proto$', editfield):
                                oldeditvalue = self.packets[self.editid][IP].proto
                                self.packets[self.editid].getlayer(IP).proto = int(editvalue)
                                print '%6d: IP.proto: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(IP).proto)
                            elif re.search(r'(?i)^chksum$', editfield):
                                oldeditvalue = self.packets[self.editid][IP].chksum
                                self.packets[self.editid].getlayer(IP).chksum = int(editvalue)
                                print '%6d: IP.chksum: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(IP).chksum)
                                self.customipchksum = True
                            elif re.search(r'(?i)^src$', editfield):
                                oldeditvalue = self.packets[self.editid][IP].src
                                self.packets[self.editid].getlayer(IP).src = str(editvalue)
                                print '%6d: IP.src: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(IP).src)
                            elif re.search(r'(?i)^dst$', editfield):
                                oldeditvalue = self.packets[self.editid][IP].dst
                                self.packets[self.editid].getlayer(IP).dst = str(editvalue)
                                print '%6d: IP.dst: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(IP).dst)
                            elif re.search(r'(?i)^options$', editfield):
                                oldeditvalue = self.packets[self.editid][IP].options
                                self.packets[self.editid].getlayer(IP).options = str(editvalue)
                                print '%6d: IP.options: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(IP).options)

                    elif re.search(r'(?i)^tcp$', editproto):
                        editproto = 'TCP'
                        if self.packets[self.editid].haslayer(editproto):
                            if re.search(r'(?i)^sport$', editfield):
                                oldeditvalue = self.packets[self.editid][TCP].sport
                                self.packets[self.editid].getlayer(TCP).sport = int(editvalue)
                                print '%6d: TCP.sport: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(TCP).sport)
                            elif re.search(r'(?i)^dport$', editfield):
                                oldeditvalue = self.packets[self.editid][TCP].dport
                                self.packets[self.editid].getlayer(TCP).dport = int(editvalue)
                                print '%6d: TCP.dport: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(TCP).dport)
                            elif re.search(r'(?i)^seq$', editfield):
                                oldeditvalue = self.packets[self.editid][TCP].seq
                                self.packets[self.editid].getlayer(TCP).seq = int(editvalue)
                                print '%6d: TCP.seq: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(TCP).seq)
                            elif re.search(r'(?i)^ack$', editfield):
                                oldeditvalue = self.packets[self.editid][TCP].ack
                                self.packets[self.editid].getlayer(TCP).ack = int(editvalue)
                                print '%6d: TCP.ack: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(TCP).ack)
                            elif re.search(r'(?i)^dataofs$', editfield):
                                oldeditvalue = self.packets[self.editid][TCP].dataofs
                                self.packets[self.editid].getlayer(TCP).dataofs = int(editvalue)
                                print '%6d: TCP.dataofs: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(TCP).dataofs)
                            elif re.search(r'(?i)^reserved$', editfield):
                                oldeditvalue = self.packets[self.editid][TCP].reserved
                                self.packets[self.editid].getlayer(TCP).reserved = int(editvalue)
                                print '%6d: TCP.reserved: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(TCP).reserved)
                            elif re.search(r'(?i)^flags$', editfield):
                                oldeditvalue = self.packets[self.editid][TCP].flags
                                self.packets[self.editid].getlayer(TCP).flags = int(editvalue)
                                print '%6d: TCP.flags: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(TCP).flags)
                            elif re.search(r'(?i)^window$', editfield):
                                oldeditvalue = self.packets[self.editid][TCP].window
                                self.packets[self.editid].getlayer(TCP).window = int(editvalue)
                                print '%6d: TCP.window: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(TCP).window)
                            elif re.search(r'(?i)^chksum$', editfield):
                                oldeditvalue = self.packets[self.editid][TCP].chksum
                                self.packets[self.editid].getlayer(TCP).chksum = int(editvalue)
                                print '%6d: TCP.chksum: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(TCP).chksum)
                                customtcpchksum = True
                            elif re.search(r'(?i)^urgptr$', editfield):
                                oldeditvalue = self.packets[self.editid][TCP].urgptr
                                self.packets[self.editid].getlayer(TCP).urgptr = int(editvalue)
                                print '%6d: TCP.urgptr: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(TCP).urgptr)
                            elif re.search(r'(?i)^options$', editfield):
                                oldeditvalue = self.packets[self.editid][TCP].options
                                self.packets[self.editid].getlayer(TCP).options = (editvalue)
                                print '%6d: TCP.options: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(TCP).options)

                    elif re.search(r'(?i)^udp$', editproto):
                        editproto = 'UDP'
                        if self.packets[self.editid].haslayer(editproto):
                            if re.search(r'(?i)^sport$', editfield):
                                oldeditvalue = self.packets[self.editid][UDP].sport
                                self.packets[self.editid].getlayer(UDP).sport = int(editvalue)
                                print '%6d: UDP.sport: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(UDP).sport)
                            elif re.search(r'(?i)^dport$', editfield):
                                oldeditvalue = self.packets[self.editid][UDP].dport
                                self.packets[self.editid].getlayer(UDP).dport = int(editvalue)
                                print '%6d: UDP.sport: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(UDP).dport)
                            if re.search(r'(?i)^len$', editfield):
                                oldeditvalue = self.packets[self.editid][UDP].len
                                self.packets[self.editid].getlayer(UDP).len = int(editvalue)
                                print '%6d: UDP.len: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(UDP).len)
                            elif re.search(r'(?i)^chksum$', editfield):
                                oldeditvalue = self.packets[self.editid][UDP].chksum
                                self.packets[self.editid].getlayer(UDP).chksum = int(editvalue)
                                print '%6d: UDP.chksum: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(UDP).chksum)

                    elif re.search(r'(?i)^dns$', editproto):
                        editproto = 'DNS'
                        if self.packets[self.editid].haslayer(editproto):
                            if re.search(r'(?i)^id$', editfield):
                                oldeditvalue = self.packets[self.editid][DNS].id
                                self.packets[self.editid].getlayer(DNS).id = int(editvalue)
                                print '%6d: DNS.id: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(DNS).id)
                            elif re.search(r'(?i)^qr$', editfield):
                                oldeditvalue = self.packets[self.editid][DNS].qr
                                self.packets[self.editid].getlayer(DNS).qr = int(editvalue)
                                print '%6d: DNS.qr: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(DNS).qr)
                            elif re.search(r'(?i)^opcode$', editfield):
                                oldeditvalue = self.packets[self.editid][DNS].opcode
                                self.packets[self.editid].getlayer(DNS).opcode = int(editvalue)
                                print '%6d: DNS.opcode: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(DNS).opcode)
                            elif re.search(r'(?i)^aa$', editfield):
                                oldeditvalue = self.packets[self.editid][DNS].aa
                                self.packets[self.editid].getlayer(DNS).aa = int(editvalue)
                                print '%6d: DNS.aa: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(DNS).aa)
                            elif re.search(r'(?i)^tc$', editfield):
                                oldeditvalue = self.packets[self.editid][DNS].tc
                                self.packets[self.editid].getlayer(DNS).tc = int(editvalue)
                                print '%6d: DNS.tc: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(DNS).tc)
                            elif re.search(r'(?i)^rd$', editfield):
                                oldeditvalue = self.packets[self.editid][DNS].rd
                                self.packets[self.editid].getlayer(DNS).rd = int(editvalue)
                                print '%6d: DNS.rd: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(DNS).rd)
                            elif re.search(r'(?i)^ra$', editfield):
                                oldeditvalue = self.packets[self.editid][DNS].ra
                                self.packets[self.editid].getlayer(DNS).ra = int(editvalue)
                                print '%6d: DNS.ra: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(DNS).ra)
                            elif re.search(r'(?i)^z$', editfield):
                                oldeditvalue = self.packets[self.editid][DNS].z
                                self.packets[self.editid].getlayer(DNS).z = int(editvalue)
                                print '%6d: DNS.z: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(DNS).z)
                            elif re.search(r'(?i)^rcode$', editfield):
                                oldeditvalue = self.packets[self.editid][DNS].rcode
                                self.packets[self.editid].getlayer(DNS).rcode = int(editvalue)
                                print '%6d: DNS.rcode: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(DNS).rcode)
                            elif re.search(r'(?i)^qdcount$', editfield):
                                oldeditvalue = self.packets[self.editid][DNS].qdcount
                                self.packets[self.editid].getlayer(DNS).qdcount = int(editvalue)
                                print '%6d: DNS.qdcount: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(DNS).qdcount)
                            elif re.search(r'(?i)^ancount$', editfield):
                                oldeditvalue = self.packets[self.editid][DNS].ancount
                                self.packets[self.editid].getlayer(DNS).ancount = int(editvalue)
                                print '%6d: DNS.ancount: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(DNS).ancount)
                            elif re.search(r'(?i)^nscount$', editfield):
                                oldeditvalue = self.packets[self.editid][DNS].nscount
                                self.packets[self.editid].getlayer(DNS).nscount = int(editvalue)
                                print '%6d: DNS.nscount: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(DNS).nscount)
                            elif re.search(r'(?i)^arcount$', editfield):
                                oldeditvalue = self.packets[self.editid][DNS].arcount
                                self.packets[self.editid].getlayer(DNS).arcount = int(editvalue)
                                print '%6d: DNS.arcount: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(DNS).arcount)
                            elif re.search(r'(?i)^qd$', editfield):
                                oldeditvalue = self.packets[self.editid][DNS].qd
                                self.packets[self.editid].getlayer(DNS).qd = int(editvalue)
                                print '%6d: DNS.qd: %s -> %s' % (self.editid, ''.join(c for c in str(oldeditvalue) if 31 < ord(c) < 127), self.packets[self.editid].getlayer(DNS).qd)
                            elif re.search(r'(?i)^an$', editfield):
                                oldeditvalue = self.packets[self.editid][DNS].an
                                self.packets[self.editid].getlayer(DNS).an = int(editvalue)
                                print '%6d: DNS.an: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(DNS).an)
                            elif re.search(r'(?i)^ns$', editfield):
                                oldeditvalue = self.packets[self.editid][DNS].ns
                                self.packets[self.editid].getlayer(DNS).ns = int(editvalue)
                                print '%6d: DNS.ns: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(DNS).ns)
                            elif re.search(r'(?i)^ar$', editfield):
                                oldeditvalue = self.packets[self.editid][DNS].ar
                                self.packets[self.editid].getlayer(DNS).ar = int(editvalue)
                                print '%6d: DNS.ar: %s -> %s' % (self.editid, oldeditvalue, self.packets[self.editid].getlayer(DNS).ar)

                    else:
                        print 'Unknown proto: %s' % (editproto)

                else:
                    print 'No editid to set!'
            else:
                self.help_set()
        else:
            print 'Nothing to set! Use \'analyze\' first.'

    def do_save(self, line):
        if self.packets and len(self.packets) > 0:
            if line != '':
		if re.search(r'\d+\s*-\s*\d+', line):
			start = int(re.findall(r'\d+', line)[0])
			end = int(re.findall(r'\d+', line)[-1])
			if start < 0: start = 0
			if end >= (len(self.packets) - 1): end = (len(self.packets) - 1)
			print 'Saving from %d to %d' % (start, end)
			outpackets = []
			for id in range(start, end+1):
				outpackets.append(self.packets[id])
			pcapnamelist = self.inpcap.split('.')
			ext = pcapnamelist[-1]
			del pcapnamelist[-1]
			pcapnamelist.append('mod')
			pcapnamelist.append(ext)
			self.outpcap = '.'.join(pcapnamelist)
			wrpcap(self.outpcap, outpackets)
			print 'Wrote %d packets to %s' % (len(self.packets), self.outpcap)
		else:
			print 'parsing as a list'
	    else:
		pcapnamelist = self.inpcap.split('.')
		ext = pcapnamelist[-1]
		del pcapnamelist[-1]
		pcapnamelist.append('mod')
		pcapnamelist.append(ext)
		self.outpcap = '.'.join(pcapnamelist)
		wrpcap(self.outpcap, self.packets)
		print 'Wrote %d packets to %s' % (len(self.packets), self.outpcap)
        else:
            print 'Nothing to save! Use \'analyze\' first.'

    def help_commands(self):
        print 'USAGE: commands'
        print 'Show a listing of available pcapedit commands'

    def do_commands(self, line):
        print
        print '\t[01] analyze ......... loads a pcap for analysis'
        print '\t[02] ls .............. list packet details'
        print '\t[03] summary ......... show summary of a packet'
        print '\t[04] hexdump ......... show hexdump of a packet'
        print '\t[05] pdfdump ......... dump packet to a PDF'
        print '\t[06] scapycmd ........ show Scapy command to generate a packet'
        print '\t[07] wireshark ....... show a packet in Wireshark'
        print '\t[08] edit ............ select a packet for set operations'
        print '\t[09] set ............. change value of a protocol field'
        print '\t[10] save ............ save packets to a pcap'
        print

if __name__ == '__main__':
    ed = editor()
    ed.cmdloop()

