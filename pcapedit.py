#!/usr/bin/env python


import os, sys
import cmd, colorama

from datetime import datetime

import logging
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
from scapy.all import *
from scapy.utils import *


class editor(cmd.Cmd):

	intro = 'PcapEdit - An Interactive Pcap Editor\n'
	prompt = '>>> '

	packets = []

	srcpcap = None
	dstpcap = None
	packets = None

	smac = None
	dmac = None

	sip = None
	dip = None

	sport = None
	dport = None

	editid = None

	def help_load(self):
		print 'USAGE: loadpcap <pcapfile>'

	def do_load(self, line):
		if line != '':
			if os.path.isfile(line):
				self.srcpcap = line
				self.packets = rdpcap(line)
				print 'read %d packets from %s' % (len(self.packets), self.srcpcap)
			else:
				print '%s doesn\'t exist!' % (line)
		else:
			self.help_load()

	def help_listall(self):
		print 'USAGE: listall'

	def do_listall(self, line):
		if self.packets and len(self.packets) > 0:
			id = 0
			for packet in self.packets:
				ptime = datetime.fromtimestamp(packet.time).strftime('%Y/%m/%d %H:%M:%S')
				data = None
				if IP in packet:
					sip = packet[IP].src
					dip = packet[IP].dst

				if TCP in packet:
					l4proto = 'TCP'
					sport = packet[TCP].sport
					dport = packet[TCP].dport
					flags = packet[TCP].flags
				elif UDP in packet:
					l4proto = 'UDP'
					sport = packet[UDP].sport
					dport = packet[UDP].dport
					flags = 0

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
						summary = ''

				print '%6d: %-15s %23s -> %-21s %3s %s' % (
						id,
						ptime,
						'%s:%s' % (sip, sport),
						'%s:%s' % (dip, dport),
						l4proto,
						summary)

				id += 1
		else:
			print 'nothing to list!'

	def help_hexdump(self):
		print 'USAGE: hexdump <packetid>'

	def do_hexdump(self, line):
		if self.packets and len(self.packets) > 0:
			if line != '':
				id = int(line)
				if id >= 0 and id <= (len(self.packets) - 1):
					print hexdump(self.packets[id])
				else:
					print 'packet %d not found! available %d - %d' % (
							id,
							1,
							len(self.packets))
			else:
				self.help_hexdump()
		else:
			print 'nothing to hexdump!'

	def do_help(self, line):
		pass

	def help_ls(self):
		print 'USAGE: ls <packetid>'

	def do_ls(self, line):
		if self.packets and len(self.packets) > 0:
			if line != '':
				id = int(line)
				if id >= 0 and id <= (len(self.packets) - 1):
					print ls(self.packets[id])
				else:
					print 'packet %d not found! available %d - %d' % (
							id,
							1,
							len(self.packets))
			else:
				self.help_ls()
		else:
			print 'nothing to ls!'


	def help_edit(self):
		print 'USAGE: edit <packetid>'

	def do_edit(self, line):
		if self.packets and len(self.packets) > 0:
			if line != '':
				id = int(line)
				if id >= 0 and id <= (len(self.packets) - 1):
					self.editid = id
					print 'editing packet id %d' % (
							self.editid)
				else:
					print 'packet %d not found! available %d - %d' % (
							id,
							1,
							len(self.packets))
			else:
				self.help_edit()
		else:
			print 'nothing to edit!'



	def help_summary(self):
		print 'USAGE: summary <packetid>'

	def do_summary(self, line):
		if self.packets and len(self.packets) > 0:
			if line != '':
				id = int(line)
				if id >= 0 and id <= (len(self.packets) - 1):
					print self.packets[id].summary()
				else:
					print 'packet %d not found! available %d - %d' % (
							id,
							1,
							len(self.packets))
			else:
				self.help_summary()
		else:
			print 'nothing to summarize!'

	def help_show(self):
		print 'USAGE: show <packetid>'

	def do_show(self, line):
		if self.packets and len(self.packets) > 0:
			if line != '':
				id = int(line)
				if id >= 0 and id <= (len(self.packets) - 1):
					print self.packets[id].show()
				else:
					print 'packet %d not found! available %d - %d' % (
							id,
							1,
							len(self.packets))
			else:
				self.help_show()
		else:
			print 'nothing to show!'

	def help_show2(self):
		print 'USAGE: show2 <packetid>'

	def do_show2(self, line):
		if self.packets and len(self.packets) > 0:
			if line != '':
				id = int(line)
				if id >= 0 and id <= (len(self.packets) - 1):
					print self.packets[id].show2()
				else:
					print 'packet %d not found! available %d - %d' % (
							id,
							1,
							len(self.packets))
			else:
				self.help_show2()
		else:
			print 'nothing to show2!'

	def help_pdfdump(self):
		print 'USAGE: pdfdump <packetid>'

	def do_pdfdump(self, line):
		if self.packets and len(self.packets) > 0:
			if line != '':
				id = int(line)
				if id >= 0 and id <= (len(self.packets) - 1):
					print self.packets[id].pdfdump()
				else:
					print 'packet %d not found! available %d - %d' % (
							id,
							1,
							len(self.packets))
			else:
				self.help_pdfdump()
		else:
			print 'nothing to dump!'

	def help_scapycmd(self):
		print 'USAGE: scapycmd <packetid>'

	def do_scapycmd(self, line):
		if self.packets and len(self.packets) > 0:
			if line != '':
				id = int(line)
				if id >= 0 and id <= (len(self.packets) - 1):
					print self.packets[id].command()
				else:
					print 'packet %d not found! available %d - %d' % (
							id,
							1,
							len(self.packets))
			else:
				self.help_scapycmd()
		else:
			print 'nothing to show command!'

	def help_wireshark(self):
		print 'USAGE: scapycmd [packetid]'

	def do_wireshark(self, line):
		if self.packets and len(self.packets) > 0:
			if line != '':
				id = int(line)
				if id >= 0 and id <= (len(self.packets) - 1):
					wireshark(self.packets[id])
				else:
					print 'packet %d not found! available %d - %d' % (
							id,
							1,
							len(self.packets))
			else:
				wireshark(self.packets)
		else:
			print 'nothing to show in wireshark!'

	def do_EOF(self, line):
		print
		return True


if __name__ == '__main__':
	ed = editor()
	ed.cmdloop()

