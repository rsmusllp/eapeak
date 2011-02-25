"""
	-*- coding: utf-8 -*-
	parse.py
	Provided by Package: eapeak
	
	Author: Spencer McIntyre <smcintyre@securestate.com>
	
	Copyright 2011 SecureState
	
	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.
	
	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
	
	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
	MA 02110-1301, USA.
		
"""
import os
import sys
#import signal
try:
	import curses
	CURSES_CAPABLE = True
except ImportError:
	CURSES_CAPABLE = False
from struct import unpack
from time import sleep

from scapy.utils import rdpcap
import scapy.packet
import scapy.layers.all
from scapy.sendrecv import sniff

import eapeak.networks 
import eapeak.clients

# Statics
UNKNOWN_SSID_NAME = 'UNKNOWN_SSID'
SSID_SEARCH_RECURSION = 5
BSSID_SEARCH_RECURSION = 3
BSSIDPositionMap = { 0:'3', 1:'1', 2:'2', 8:'3', 9:'1', 10:'2' }
SourcePositionMap = { 0:'2', 1:'2', 2:'3', 8:'2', 9:'2', 10:'3' }
DestinationPositionMap = { 0:'1', 1:'3', 2:'1', 8:'1', 9:'3', 10:'1' }
CURSES_LINE_BREAK = [0, '']
CURSES_REFRESH_FREQUENCY = 0.25
CURSES_MIN_X = 99		# minimum screen size
CURSES_MIN_Y = 25
TAB_LENGTH = 4	# in spaces

USER_MARKER = '=> '
USER_MARKER_OFFSET = 8
SSID_MAX_LENGTH = 32
from scapy.layers.l2 import eap_types as EAP_TYPES
EAP_TYPES[0] = 'NONE'

def getBSSID(packet):
	tmppacket = packet
	for x in range(0, BSSID_SEARCH_RECURSION):	
		if not tmppacket.fields.has_key('FCfield'):
			tmppacket = tmppacket.payload
			continue
		if tmppacket.fields['FCfield'] in BSSIDPositionMap:
			if tmppacket.fields.has_key('addr' + BSSIDPositionMap[tmppacket.fields['FCfield']]):
				return tmppacket.fields['addr' + BSSIDPositionMap[tmppacket.fields['FCfield']]]
			else:
				return None # something is invalid
		else:
			return None # somthing is invalid
	return None
	
def getSource(packet):
	tmppacket = packet
	for x in range(0, BSSID_SEARCH_RECURSION):	
		if not tmppacket.fields.has_key('FCfield'):
			tmppacket = tmppacket.payload
			continue
		if tmppacket.fields['FCfield'] in SourcePositionMap:
			if tmppacket.fields.has_key('addr' + SourcePositionMap[tmppacket.fields['FCfield']]):
				return tmppacket.fields['addr' + SourcePositionMap[tmppacket.fields['FCfield']]]
			else:
				return None # something is invalid
		else:
			return None # somthing is invalid
	return None
	
def getDestination(packet):
	tmppacket = packet
	for x in range(0, BSSID_SEARCH_RECURSION):	
		if not tmppacket.fields.has_key('FCfield'):
			tmppacket = tmppacket.payload
			continue
		if tmppacket.fields['FCfield'] in DestinationPositionMap:
			if tmppacket.fields.has_key('addr' + DestinationPositionMap[tmppacket.fields['FCfield']]):
				return tmppacket.fields['addr' + DestinationPositionMap[tmppacket.fields['FCfield']]]
			else:
				return None # something is invalid
		else:
			return None # somthing is invalid
	return None
	
def mergeWirelessNetworks(source, destination):
	for bssid in source.bssids:
		destination.addBSSID(bssid)
	
	for mac, clientobj in source.clients.items():
		destination.addClient(clientobj)
		
	for eapType in source.eapTypes:
		destination.addEapType(eapType)
	return destination

class EapeakParsingEngine:
	"""
	This is the main engine that manages all of the networks.
	"""
	def __init__(self, targetSSIDs = []):
		self.KnownNetworks = { }							# holds wireless network objects, indexed by SSID if available, BSSID if orphaned
		self.BSSIDToSSIDMap = { }							# holds SSIDs, indexed by BSSIDS, so you can obtain network objects by BSSID
		self.OrphanedBSSIDs = [ ]							# holds BSSIDs that are not associated with a known SSID
		self.packets = [ ]
		self.targetSSIDs = targetSSIDs
		self.packetCounter = 0
		self.curses_enabled = False
		
	def cleanupCurses(self):
		self.screen.erase()
		del self.screen
		curses.endwin()
		curses.echo()
		self.curses_enabled = False
		
	def initCurses(self):
		self.user_marker_pos = 1							# used with curses
		self.curses_row_offset = 0							# used for marking the visible rows on the screen to allow scrolling
		self.curses_detailed = None							# used with curses
		self.screen = curses.initscr()
		size = self.screen.getmaxyx()
		if size[0] < CURSES_MIN_Y or size[1] < CURSES_MIN_X:
			curses.endwin()
			return 1
		self.curses_max_rows = size[0] - 2					# minus 2 for the border on the top and bottom
		self.curses_max_columns = size[1] - 2
		self.screen.border(0)
		self.screen.addstr(2, TAB_LENGTH, 'EAPeak Capturing Live')
		self.screen.addstr(3, TAB_LENGTH, 'Found 0 Networks')
		self.screen.addstr(4, TAB_LENGTH, 'Processed 0 Packets')
		self.screen.addstr(self.user_marker_pos + USER_MARKER_OFFSET, TAB_LENGTH, USER_MARKER)
		self.screen.refresh()
		curses.curs_set(0)
		curses.noecho()
		self.curses_enabled = True
		#signal.signal(signal.SIGWINCH, self.cursesSigwinchHandler )
		return 0
		
	def parseLiveCapture(self, packet, quite = True):
		self.packetCounter += 1
		self.parseWirelessPacket(packet)
		if not self.curses_enabled or quite:
			return
		sys.stdout.write('Packets: ' + str(self.packetCounter) + ' Wireless Networks: ' + str(len(self.KnownNetworks)) + '\r')
		sys.stdout.flush()
		
	def parsePCapFiles(self, pcapFiles, quite = True):
		for i in range(0, len(pcapFiles)):
			pcap = pcapFiles[i]
			pcapName = os.path.split(pcap)[1]
			if not quite:
				sys.stdout.write("Reading PCap File: {0}\r".format(pcapName))
				sys.stdout.flush()
			if not os.path.isfile(pcap) or not os.access(pcap, os.R_OK):
				if not quite:
					sys.stdout.write("Skipping File {0} Due To Read Issue\n".format(pcap))
					sys.stdout.flush()
				continue
			try:
				self.packets.extend(rdpcap(pcapFiles[i]))
			except KeyboardInterrupt:
				if not quite:
					sys.stdout.write("Skipping File {0} Due To Ctl+C\n".format(pcap))
					sys.stdout.flush()
			except:
				if not quite:
					sys.stdout.write("Skipping File {0} Due To Scapy Exception\n".format(pcap))
					sys.stdout.flush()
				continue
			for i in range(0, len(self.packets)):
				if not quite:
					sys.stdout.write("Parsing PCap File: {} {:,} of {:,} Packets Done\r".format(pcapName, i + 1, len(self.packets)))
					sys.stdout.flush()	
				packet = self.packets[i]
				self.parseWirelessPacket(packet)
			if not quite:
				sys.stdout.write("Parsing PCap File: {} {:,} of {:,} Packets Done\n".format(pcapName, i + 1, len(self.packets)))
				sys.stdout.flush()
			self.packets = [ ]
			
	def parseWirelessPacket(self, packet):
		shouldStop = False
		
		# this section finds SSIDs in Bacons, I don't like this section, but I do like bacon
		if packet.haslayer('Dot11Beacon') or packet.haslayer('Dot11ProbeResp') or packet.haslayer('Dot11AssoReq'):
			tmp = packet
			for x in range(0, SSID_SEARCH_RECURSION):
				if 'ID' in tmp.fields and tmp.fields['ID'] == 0 and 'info' in tmp.fields:	# this line verifies that we found an SSID
					if tmp.fields['info'] == '\x00':
						break	# null SSIDs are useless
					if self.targetSSIDs and tmp.fields['info'] not in self.targetSSIDs:	# these are not the SSIDs you are looking for
						break
					bssid = getBSSID(packet)
					if not bssid:
						return
					ssid = ''.join([c for c in tmp.fields['info'] if ord(c) > 31 or ord(c) == 9])
					if not ssid:
						return
					if bssid in self.OrphanedBSSIDs:								# if this info is relating to a BSSID that was previously considered to be orphaned
						newNetwork = self.KnownNetworks[bssid]						# retrieve the old one
						del self.KnownNetworks[bssid]								# delete the old network's orphaned reference
						self.OrphanedBSSIDs.remove(bssid)
						self.BSSIDToSSIDMap[bssid] = ssid							# this changes the map from BSSID -> BSSID (for orphans) to BSSID -> SSID
						newNetwork.updateSSID(ssid)
						if ssid in self.KnownNetworks:
							newNetwork = mergeWirelessNetworks(newNetwork, self.KnownNetworks[ ssid ])
					elif bssid in self.BSSIDToSSIDMap:
						continue
					elif ssid in self.KnownNetworks:								# this is a BSSID from a probe for an SSID we've seen before
						newNetwork = self.KnownNetworks[ ssid ]
					elif bssid:
						newNetwork = eapeak.networks.WirelessNetwork(ssid)
						self.BSSIDToSSIDMap[bssid] = ssid
					newNetwork.addBSSID(bssid)
					
					self.KnownNetworks[ssid] = newNetwork
					del bssid, ssid
					break
				tmp = tmp.payload
				if tmp == None:
					break
			shouldStop = True
		if shouldStop:
			return
					
		# this section extracts useful EAP info
		if 'EAP' in packet:
			fields = packet.getlayer('EAP').fields
			if fields['code'] not in [1, 2]:
				return
			eaptype = fields['type']
			for x in range(1, 4):
				addr = 'addr' + str(x)	# outputs addr1 - 3
				if not packet.fields.has_key(addr):
					return
				addr = packet.fields[addr]
				bssid = getBSSID(packet)
				if not bssid:
					return
				if bssid and not bssid in self.BSSIDToSSIDMap:
					self.BSSIDToSSIDMap[bssid] = bssid
					self.OrphanedBSSIDs.append(bssid)
					self.KnownNetworks[bssid] = eapeak.networks.WirelessNetwork(UNKNOWN_SSID_NAME)
					self.KnownNetworks[bssid].addBSSID(bssid)
				network = self.KnownNetworks[self.BSSIDToSSIDMap[bssid]]				# objects should be returned as pointers, network to client should affect the client object as still in the BSSIDMap
				bssid = getBSSID(packet)
				client_mac = getSource(packet)
				from_AP = False
				if client_mac == bssid:
					client_mac = getDestination(packet)
					from_AP = True
				if not bssid or not client_mac:
					return # something went wrong
				if network.hasClient(client_mac):
					client = network.getClient(client_mac)
				else:
					client = eapeak.clients.WirelessClient(bssid, client_mac)
				if from_AP:
					network.addEapType(eaptype)
				elif not eaptype in [1, 3]:
					client.addEapType(eaptype)
				elif eaptype == 3:	# this parses NAKs and attempts to harvest the desired EAP types, RFC 3748
					if packet.getlayer('EAP').payload:
						desiredTypes = []
						tmpdata = str(packet.getlayer('EAP').payload)
						for byte in tmpdata:
							desiredTypes.append(unpack('B', byte)[0])
						client.addDesiredEapTypes(desiredTypes)
						del tmpdata
				if eaptype == 1 and fields['code'] == 2 and 'identity' in fields:
					client.addIdentity(1, fields['identity'])
				if packet.haslayer('LEAP') and 'name' in packet.getlayer('EAP').payload.fields:
					identity = packet.getlayer('EAP').payload.fields['name']
					if identity:
						client.addIdentity(17, identity)
				network.addClient(client)
			shouldStop = True
		if shouldStop:
			return
		return

	def cursesInteractionHandler(self, garbage = None):
		while self.curses_enabled:
			c = self.screen.getch()
			if self.curses_detailed and c != ord('i'):
				continue
			if c == ord('u'):
				self.screen.addstr(self.user_marker_pos + USER_MARKER_OFFSET, TAB_LENGTH, ' ' * len(USER_MARKER))
				if self.user_marker_pos == 1 and self.curses_row_offset == 0:
					# ceiling
					pass
				elif self.user_marker_pos == 1 and self.curses_row_offset:
					self.curses_row_offset -= 1
				else:
					self.user_marker_pos -= 1
				self.screen.addstr(self.user_marker_pos + USER_MARKER_OFFSET, TAB_LENGTH, USER_MARKER)
				
			elif c == ord('d'):
				self.screen.addstr(self.user_marker_pos + USER_MARKER_OFFSET, TAB_LENGTH, ' ' * len(USER_MARKER))
				if self.user_marker_pos + self.curses_row_offset == len(self.KnownNetworks):
					# floor
					pass
				elif self.user_marker_pos == self.curses_max_rows - 9:
					self.curses_row_offset += 1
				else:
					self.user_marker_pos += 1
				self.screen.addstr(self.user_marker_pos + USER_MARKER_OFFSET, TAB_LENGTH, USER_MARKER)
				
			elif c == ord('i'):
				if self.curses_detailed:
					self.curses_detailed = None
					self.screen.erase()
					self.screen.border(0)
					self.screen.addstr(self.user_marker_pos + USER_MARKER_OFFSET, TAB_LENGTH, USER_MARKER)
					self.screen.refresh()
				else:
					self.curses_detailed = self.KnownNetworks.keys()[self.user_marker_pos - 1 + self.curses_row_offset]
					self.screen.erase()
					self.screen.border(0)
					self.screen.refresh()
					
	def cursesScreenDrawHandler(self):
		while self.curses_enabled:
			messages = []
			messages.append([1, 'EAPeak Capturing Live'])
			messages.append([1, 'Found ' + str(len(self.KnownNetworks)) + ' Networks'])
			messages.append([1, "Processed {:,} Packets".format(self.packetCounter)])
			messages.append(CURSES_LINE_BREAK)
			messages.append([1, 'Network Information:'])
			ssids = self.KnownNetworks.keys()
			if self.curses_detailed and self.curses_detailed in self.KnownNetworks:
				network = self.KnownNetworks[ self.curses_detailed ]
				messages.append([2, 'SSID: ' + network.ssid])
				messages.append(CURSES_LINE_BREAK)
				
				messages.append([2, 'BSSIDs:'])
				for bssid in network.bssids:
					messages.append([3, bssid])
				tmpEapTypes = []
				if network.eapTypes:
					for eType in network.eapTypes:
						if eType in EAP_TYPES:
							tmpEapTypes.append(EAP_TYPES[eType])
						else:
							tmpEapTypes.append(str(eType))
				messages.append(CURSES_LINE_BREAK)
				
				if tmpEapTypes:
					messages.append([2, 'EAP Types: ' + ", ".join(tmpEapTypes)])
				else:
					messages.append([2, 'EAP Types: [ NONE ]'])
				messages.append(CURSES_LINE_BREAK)
				
				if network.clients:
					messages.append([2, 'Clients:'])
					clients = network.clients.values()
					for i in range(0, len(clients)):
						client = clients[i]
						messages.append([3, 'Client #' + str(i + 1) ])
						messages.append([3, 'MAC: ' + client.mac])
						if client.identities:
							messages.append([3, 'Identities:'])
						for ident, eap in client.identities.items():
							messages.append([4, '(' + EAP_TYPES[eap] + ') ' + ident])
						messages.append(CURSES_LINE_BREAK)
					del clients
				else:
					messages.append([2, 'Clients: [ NONE ]'])
			else:
				messages.append([2, 'SSID:' + ' ' * (SSID_MAX_LENGTH + 1) + 'EAP Types:'])
				if self.curses_row_offset:
					messages.append([2, '[ MORE ]'])
				else:
					messages.append([2, '        '])
				for i in range(self.curses_row_offset, len(ssids)):
					if len(messages) > self.curses_max_rows - 3:
						messages.append([2, '[ MORE ]'])
						break
					network = self.KnownNetworks[ssids[i]]
					tmpEapTypes = []
					if network.eapTypes:
						for eType in network.eapTypes:
							if eType in EAP_TYPES:
								tmpEapTypes.append(EAP_TYPES[eType])
							else:
								tmpEapTypes.append(str(eType))
					if i < 10:
						messages.append([2, str(i + 1) + ') ' + network.ssid + ' ' * (SSID_MAX_LENGTH - len(network.ssid) + 4) + ", ".join(tmpEapTypes)])
					else:
						messages.append([2, str(i + 1) + ') ' + network.ssid + ' ' * (SSID_MAX_LENGTH - len(network.ssid) + 3) + ", ".join(tmpEapTypes)])
				if not len(messages) > self.curses_max_rows - 2:
					messages.append([2, '        '])
			line = 2
			for message in messages:
				self.screen.addstr(line, TAB_LENGTH * message[0], message[1])
				line += 1
			self.screen.refresh()
			sleep(CURSES_REFRESH_FREQUENCY)
	
	def cursesSigwinchHandler(self, n, frame):
		curses.endwin()
		self.screen = curses.initscr()
		size = self.screen.getmaxyx()
		if size[0] < 25 or size[1] < 99:
			curses.endwin()
			sys.exit(2)
		self.screen.border(0)
		self.screen.addstr(2, TAB_LENGTH, 'EAPeak Capturing Live')
		self.screen.addstr(3, TAB_LENGTH, 'Found 0 Networks')
		self.screen.addstr(4, TAB_LENGTH, 'Processed 0 Packets')
		self.screen.addstr(self.user_marker_pos + USER_MARKER_OFFSET, TAB_LENGTH, USER_MARKER)
		self.screen.refresh()
		return 0
