"""
	-*- coding: utf-8 -*-
	inject.py
	Provided by Package: eapeak
	
	Author: Spencer McIntyre <smcintyre [at] securestate [dot] com>
	
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

from struct import pack, unpack
from random import randint
from eapeak.parse import getBSSID, getSource, getDestination
from ipfunc import getHwAddr

from scapy.sendrecv import sniff, sendp
from scapy.layers.dot11 import *
from scapy.layers.l2 import *

RESPONSE_TIMEOUT = 1.5	# time to wait for a response

class WirelessStateMachine:
	"""
	States Are For Smashing
	"""
	def __init__(self, interface, bssid, local_mac = None):
		if not local_mac:
			local_mac = getHwAddr(interface)
		self.interface = interface
		self.bssid = bssid
		self.connected = False	# connected / associated
		self.local_mac = local_mac
		self.sequence = randint(1200, 2000)
		self.lastpacket = None
	
	def __unfuckupSC__(self, sequence, fragment = 0):
		SC = (sequence - ((sequence >> 4) << 4) << 12) + (fragment << 8) + (sequence >> 4) # bit shifts FTW!
		return unpack('<H', pack('>H', SC))[0]
		
	def __stopfilter__(self, packet):
		real_destination = getDestination(packet)
		real_bssid = getBSSID(packet)
		if real_destination == self.local_mac and real_bssid == self.bssid:
			self.lastpacket = packet
			return True
		self.lastpacket = None
		return False
		
	def connect(self, essid):
		"""
		errDict = {0:"No Error", 1:"Failed To Get Probe Response", 2:"Failed To Get Authentication Response", 3:"Failed To Get Association Response"}
		"""
		# Dot11 Probe Request
		sendp(RadioTap()/Dot11(addr1=self.bssid, addr2=self.local_mac, addr3=self.bssid, SC=self.__unfuckupSC__(self.sequence), type=0, subtype=4, ID=218)/Dot11ProbeReq()/Dot11Elt(ID=0, info=essid)/Dot11Elt(ID=1, info='\x02\x04\x0b\x16\x0c\x12\x18$')/Dot11Elt(ID=50, info='0H`l'), iface=self.interface, verbose=False)
		self.sequence += 1
		sniff(iface=self.interface, store=0, timeout=RESPONSE_TIMEOUT, stop_filter=self.__stopfilter__)
		if self.lastpacket == None:
			return 1
		
		# Dot11 Authentication Request
		sendp(RadioTap()/Dot11(addr1=self.bssid, addr2=self.local_mac, addr3=self.bssid, SC=self.__unfuckupSC__(self.sequence))/Dot11Auth(seqnum=1), iface=self.interface, verbose=False)
		self.sequence += 1
		sniff(iface=self.interface, store=0, timeout=RESPONSE_TIMEOUT, stop_filter=self.__stopfilter__)
		if self.lastpacket == None:
			return 2
		
		# Dot11 Association Request
		sendp(RadioTap()/Dot11(addr1=self.bssid, addr2=self.local_mac, addr3=self.bssid, SC=self.__unfuckupSC__(self.sequence), subtype=0)/Dot11AssoReq(cap='ESS+privacy+short-preamble+short-slot', listen_interval=10)/Dot11Elt(ID=0, info=essid)/Dot11Elt(ID=1, info='\x02\x04\x0b\x16\x0c\x12\x18$')/Dot11Elt(ID=50, info='0H`l')/Dot11Elt(ID=48, info='\x01\x00\x00\x0f\xac\x02\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x01\x00\x00')/Dot11Elt(ID=221, info='\x00P\xf2\x02\x00\x01\x00'), iface=self.interface, verbose=False)
		self.sequence += 1
		sniff(iface=self.interface, store=0, timeout=RESPONSE_TIMEOUT, stop_filter=self.__stopfilter__)
		if self.lastpacket == None:
			return 3
		
		self.connected = True
		self.sequence = 0	# reset it
		return 0
		
	def disconnect(self):
		"""
		errDict = {-1:"Not Connected", 0:"No Error"}
		"""
		if not self.connected:
			return -1
		sendp(RadioTap()/Dot11(addr1=self.bssid, addr2=self.local_mac, addr3=self.bssid, SC=self.__unfuckupSC__(self.sequence), type=0, subtype=12)/Dot11Disas(reason=3), iface=self.interface, verbose=False)
		sendp(RadioTap()/Dot11(addr1=self.bssid, addr2=self.local_mac, addr3=self.bssid, SC=self.__unfuckupSC__(self.sequence), type=0, subtype=12)/Dot11Disas(reason=3), iface=self.interface, verbose=False)
		self.connected = False
		return 0

	def check_eap_type(self, eaptype):
		"""
		errDict = {0:"supported", 1:"not supported", 2:"could not determine"}
		"""
		eap_identity_response = RadioTap()/Dot11(addr1=self.bssid, addr2=self.local_mac, addr3=self.bssid, SC=self.__unfuckupSC__(self.sequence), type=2, subtype=8, FCfield=0x01)/Dot11QoS()/LLC(dsap=170, ssap=170, ctrl=3)/SNAP(code=0x888e)/EAPOL(version=1, type=0)/EAP(code=2, type=1, identity='user')
		self.sequence += 1
		eap_legacy_nak = RadioTap()/Dot11(FCfield=0x01, addr1=self.bssid, addr2=self.local_mac, addr3=self.bssid, SC=self.__unfuckupSC__(self.sequence), type=2, subtype=8)/Dot11QoS()/LLC(dsap=170, ssap=170, ctrl=3)/SNAP(code=0x888e)/EAPOL(version=1, type=0, len=6)/EAP(code=2, type=3, id=1, eap_types=[ eaptype ])
		self.sequence += 1
		
		for i in range(0, 2):
			sendp(eap_identity_response, iface=self.interface, verbose=False)
			sniff(iface=self.interface, store=0, timeout=RESPONSE_TIMEOUT, stop_filter=self.__stopfilter__)
			if not self.lastpacket == None:
				if self.lastpacket.haslayer('EAP'):
					fields = self.lastpacket.getlayer(EAP).fields
					if 'type' in fields and fields['type'] == eaptype:
						return 0
					break
		# if i == 1: return 2 # this line makes it slower and less accurate
		
		for i in range(0, 2):
			sendp(eap_legacy_nak, iface=self.interface, verbose=False)
			sniff(iface=self.interface, store=0, timeout=RESPONSE_TIMEOUT, stop_filter=self.__stopfilter__)
			if not self.lastpacket == None:
				if self.lastpacket.haslayer('EAP'):
					fields = self.lastpacket.getlayer(EAP).fields
					if 'type' in fields and fields['type'] == eaptype:
						return 0
					else:
						return 1		
		return 2
