#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
#
#  lib/eapeak/inject.py
#
#  Author: Spencer McIntyre (Steiner) <smcintyre [at] securestate [dot] com>
#
#  Copyright 2011 SecureState
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.

__version__ = '0.0.6'

# native imports
import Queue
from random import randint
from struct import pack, unpack
import threading
import time
import threading

# project imports
from eapeak.clients import WirelessClient
from eapeak.common import getBSSID, getSource, getDestination
from eapeak.networks import WirelessNetwork
from eapeak.parse import UNKNOWN_SSID_NAME, parseRSNData, buildRSNData
from ipfunc import getHwAddr

# external imports
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11Elt, Dot11Auth, Dot11AssoReq, Dot11AssoResp, Dot11ProbeReq, Dot11Disas, Dot11QoS, Dot11ProbeResp
from scapy.layers.l2 import LLC, SNAP, EAPOL
from scapy.sendrecv import sniff, sendp
from eapeak.scapylayers.l2 import LEAP, PEAP, EAP
RESPONSE_TIMEOUT = 1.5  # Time to wait for a response
PRIVACY_NONE = 0
PRIVACY_WEP = 1
PRIVACY_WPA = 2
EAP_MAX_TRIES = 3

GOOD = '\033[1;32m[+]\033[1;m '
STATUS = '\033[1;34m[*]\033[1;m '
ERROR = '\033[1;31m[-]\033[1;m '

class SSIDBroadcaster(threading.Thread):
	"""
	This object is a thread-friendly SSID broadcaster
	It's meant to be controlled by the Wireless State Machine
	"""
	def __init__(self, interface, essid, bssid=None):
		threading.Thread.__init__(self)
		self.interface = interface
		self.essid = essid
		if not bssid:
			bssid = getHwAddr(interface)
		self.bssid = bssid.lower()
		self.broadcast_interval = 0.15
		self.channel = "\x06"
		self.setPrivacy(PRIVACY_NONE)
		self.sequence = randint(1200, 2000)
		self.__shutdown__ = False

	def __fixSC__(self, fragment=0):
		"""
		This is a reserved method to return the sequence number in a way
		that is not skewed by a bug in how the SC field is packed in
		Scapy.
		"""
		if self.sequence >= 0xFFF:
			self.sequence = 1
		else:
			self.sequence += 1
		SC = (self.sequence - ((self.sequence >> 4) << 4) << 12) + (fragment << 8) + (self.sequence >> 4)
		return unpack('<H', pack('>H', SC))[0]
		
	def run(self):
		"""
		This is the thread routine that broadcasts the SSID.
		"""
		while not self.__shutdown__:
			self.beacon.getlayer(Dot11).SC = self.__fixSC__()
			sendp(self.beacon, iface=self.interface, verbose=False)
			sleep(self.broadcast_interval)
			
	def setPrivacy(self, value):
		"""
		Configure the privacy settings for None, WEP, and WPA
		"""
		if value == PRIVACY_NONE:
			self.beacon = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.bssid, addr3=self.bssid)/Dot11Beacon(cap='ESS+short-preamble+short-slot')/Dot11Elt(ID="SSID", info=self.essid)/Dot11Elt(ID="Rates", info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/Dot11Elt(ID="DSset", info=self.channel)/Dot11Elt(ID=42, info="\x04")/Dot11Elt(ID=47, info="\x04")/Dot11Elt(ID=50, info="\x0c\x12\x18\x60")
		elif value == PRIVACY_WEP:
			self.beacon = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.bssid, addr3=self.bssid)/Dot11Beacon(cap='ESS+privacy+short-preamble+short-slot')/Dot11Elt(ID="SSID", info=self.essid)/Dot11Elt(ID="Rates", info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/Dot11Elt(ID="DSset", info=self.channel)/Dot11Elt(ID=42, info="\x04")/Dot11Elt(ID=47, info="\x04")/Dot11Elt(ID=50, info="\x0c\x12\x18\x60")
		elif value == PRIVACY_WPA:
			self.beacon = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.bssid, addr3=self.bssid)/Dot11Beacon(cap='ESS+privacy+short-preamble+short-slot')/Dot11Elt(ID="SSID", info=self.essid)/Dot11Elt(ID="Rates", info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/Dot11Elt(ID="DSset", info=self.channel)/Dot11Elt(ID=221, info="\x00\x50\xf2\x01\x01\x00" + "\x00\x50\xf2\x02" + "\x01\x00" + "\x00\x50\xf2\x02" + "\x01\x00" + "\x00\x50\xf2\x01")/Dot11Elt(ID=42, info="\x00")/Dot11Elt(ID=50, info="\x30\x48\x60\x6c")/Dot11Elt(ID=221, info="\x00\x50\xf2\x02\x01\x01\x84\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00")

	def sendBeacon(self):
		"""
		Convenience function for sending beacons without starting a thread
		"""
		self.beacon.getlayer(Dot11).SC = self.__fixSC__()
		sendp(self.beacon, iface=self.interface, verbose=False)
	
	@staticmethod
	def sendBeaconEx(essid, interface, privacy=PRIVACY_NONE, bssid=None, channel=6):
		"""
		Convenience function for sending beacons without a thread or creating an instance
		"""
		if not bssid:
			bssid = getHwAddr(interface)
		channel = chr(channel)
		sequence = randint(1200, 2000)
		
		if privacy in [PRIVACY_NONE, 'none', 'NONE']:
			beacon = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid, SC=sequence)/Dot11Beacon(cap='ESS+short-preamble+short-slot')/Dot11Elt(ID="SSID", info=essid)/Dot11Elt(ID="Rates", info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/Dot11Elt(ID="DSset", info=channel)/Dot11Elt(ID=42, info="\x04")/Dot11Elt(ID=47, info="\x04")/Dot11Elt(ID=50, info="\x0c\x12\x18\x60")
		elif privacy in [PRIVACY_WEP, 'wep', 'WEP']:
			beacon = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid, SC=sequence)/Dot11Beacon(cap='ESS+privacy+short-preamble+short-slot')/Dot11Elt(ID="SSID", info=essid)/Dot11Elt(ID="Rates", info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/Dot11Elt(ID="DSset", info=channel)/Dot11Elt(ID=42, info="\x04")/Dot11Elt(ID=47, info="\x04")/Dot11Elt(ID=50, info="\x0c\x12\x18\x60")
		elif privacy in [PRIVACY_WPA, 'wpa', 'WPA']:
			beacon = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid, SC=sequence)/Dot11Beacon(cap='ESS+privacy+short-preamble+short-slot')/Dot11Elt(ID="SSID", info=essid)/Dot11Elt(ID="Rates", info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/Dot11Elt(ID="DSset", info=channel)/Dot11Elt(ID=221, info="\x00\x50\xf2\x01\x01\x00" + "\x00\x50\xf2\x02" + "\x01\x00" + "\x00\x50\xf2\x02" + "\x01\x00" + "\x00\x50\xf2\x01")/Dot11Elt(ID=42, info="\x00")/Dot11Elt(ID=50, info="\x30\x48\x60\x6c")/Dot11Elt(ID=221, info="\x00\x50\xf2\x02\x01\x01\x84\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00")
		else:
			raise Exception('Invalid privacy setting')
		sendp(beacon, iface=interface, verbose=False)
		
class ClientListener(threading.Thread):
	"""
	This object is a thread-friendly listener for Client connection
	attempts.
	
	The backlog corresponds to the size of the queue, if the queu is
	full because the items are not being handled fast enough then new
	association requests will be dropped and lost.
	"""
	def __init__(self, interface, backlog, essid=None, bssid=None):
		threading.Thread.__init__(self)
		self.interface = interface
		self.backlog = backlog
		self.essid = essid
		if not bssid:
			bssid = getHwAddr(interface)
		self.bssid = bssid.lower()
		self.lastpacket = None
		self.client_queue = Queue.Queue(self.backlog)
		self.channel = "\x06"
		self.sequence = randint(1200, 2000)
		self.__shutdown__ = False
		
	def __fixSC__(self, fragment=0):
		"""
		This is a reserved method to return the sequence number in a way
		that is not skewed by a bug in how the SC field is packed in
		Scapy.
		"""
		if self.sequence >= 0xFFF:
			self.sequence = 1
		else:
			self.sequence += 1
		SC = (self.sequence - ((self.sequence >> 4) << 4) << 12) + (fragment << 8) + (self.sequence >> 4) # bit shifts FTW!
		return unpack('<H', pack('>H', SC))[0]
		
	def __stopfilter__(self, packet):
		"""
		This is the stop filter for Scapy to be used to check if the
		packet was sent to EAPeak.
		"""
		if (packet.haslayer(Dot11Auth) or packet.haslayer(Dot11AssoReq)):
			if getBSSID(packet) == self.bssid and getSource(packet) != self.bssid:
				self.lastpacket = packet
				return True
			return False
		elif packet.haslayer(Dot11ProbeReq):
			self.lastpacket = packet
			return True
		return False
			
	def setPrivacy(self, value):
		"""
		Configure the privacy settings for None, WEP, and WPA
		"""
		if value == PRIVACY_NONE:
			self.probe_response_template = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.bssid, addr3=self.bssid)/Dot11ProbeResp(cap='ESS+privacy+short-preamble+short-slot')/Dot11Elt(ID="SSID", info='')/Dot11Elt(ID="Rates", info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/Dot11Elt(ID="DSset", info=self.channel)/Dot11Elt(ID=42, info="\x04")/Dot11Elt(ID=47, info="\x04")/Dot11Elt(ID=50, info="\x0c\x12\x18\x60")
		elif value == PRIVACY_WEP:
			self.probe_response_template = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.bssid, addr3=self.bssid)/Dot11ProbeResp(cap='ESS+short-preamble+short-slot')/Dot11Elt(ID="SSID", info='')/Dot11Elt(ID="Rates", info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/Dot11Elt(ID="DSset", info=self.channel)/Dot11Elt(ID=42, info="\x04")/Dot11Elt(ID=47, info="\x04")/Dot11Elt(ID=50, info="\x0c\x12\x18\x60")
		elif value == PRIVACY_WPA:
			self.probe_response_template = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.bssid, addr3=self.bssid)/Dot11ProbeResp(cap='ESS+privacy+short-preamble+short-slot')/Dot11Elt(ID="SSID", info='')/Dot11Elt(ID="Rates", info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/Dot11Elt(ID="DSset", info=self.channel)/Dot11Elt(ID=221, info="\x00\x50\xf2\x01\x01\x00" + "\x00\x50\xf2\x02" + "\x01\x00" + "\x00\x50\xf2\x02" + "\x01\x00" + "\x00\x50\xf2\x01")/Dot11Elt(ID=42, info="\x00")/Dot11Elt(ID=50, info="\x30\x48\x60\x6c")/Dot11Elt(ID=221, info="\x00\x50\xf2\x02\x01\x01\x84\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00")
		
	def run(self):
		"""
		This is the thread routine that handles probe requests and sends
		probe responses when appropriate.
		"""
		while not self.__shutdown__:
			sniff(iface=self.interface, store=0, timeout=RESPONSE_TIMEOUT, stop_filter=self.__stopfilter__)
			if self.lastpacket:
				if self.lastpacket.haslayer(Dot11ProbeReq):
					ssid = None
					tmp = self.lastpacket.getlayer(Dot11ProbeReq)
					while tmp:
						tmp = tmp.payload
						if tmp.fields['ID'] == 0:
							ssid = tmp.info
							break
					if ssid is None:
						continue
					elif ssid == '' and self.essid:
						ssid = self.essid
					if self.essid is None or self.essid == ssid:
						self.probe_response_template.getlayer(Dot11).addr1 = getSource(self.lastpacket)
						self.probe_response_template.getlayer(Dot11Elt).info = ssid
						sendp(self.probe_response_template, iface=self.interface, verbose=False)
					self.lastpacket = None
					continue
				clientMAC = getSource(self.lastpacket)
				if not self.client_queue.full():
					self.client_queue.put(clientMAC, False)
				self.lastpacket = None
				continue

class WirelessStateMachine:
	"""
	This provides a psuedo-socket like object that provides a stack for
	Dot11 communications using Scapy.
	
	Remember:
	States Are For Smashing
	"""
	def __init__(self, interface, bssid, source_mac=None, dest_mac=None):
		"""
		You must specify a BSSID and a Local MAC address because the
		entire point of this code is to facilitate stateful connections.
		"""
		if not source_mac:
			source_mac = getHwAddr(interface)
		if not dest_mac:
			dest_mac = bssid
		self.interface = interface
		
		self.bssid = bssid.lower()
		self.source_mac = source_mac.lower()
		self.dest_mac = dest_mac.lower()
		
		self.connected = False  # connected / associated
		self.__shutdown__ = False
		self.sequence = randint(1200, 2000)
		self.lastpacket = None
		self.timeout = RESPONSE_TIMEOUT
		
	def __del__(self):
		self.shutdown()
		self.close()
	
	def __fixSC__(self, fragment=0):
		"""
		This is a reserved method to return the sequence number in a way
		that is not skewed by a bug in how the SC field is packed in
		Scapy.
		"""
		SC = (self.sequence - ((self.sequence >> 4) << 4) << 12) + (fragment << 8) + (self.sequence >> 4)
		return unpack('<H', pack('>H', SC))[0]
		
	def __stopfilter__(self, packet):
		"""
		This is the stop filter for Scapy to be used to check if the
		packet was sent to this WirelessStateMachine instance.
		"""
		if getDestination(packet) == self.source_mac and getBSSID(packet) == self.bssid:  # and real_source == self.dest_mac:
			self.lastpacket = packet
			return True
		self.lastpacket = None
		return False
		
	def connect(self, essid, rsnInfo=''):
		"""
		Connect/Associate with an access point.
		errDict = {
			-1:"Already Connected",
			0:"No Error",
			1:"Failed To Get Probe Response",
			2:"Failed To Get Authentication Response",
			3:"Failed To Get Association Response",
			4:"Authentication Request Received Fail Response",
			5:"Association Request Received Fail Response"
		}
		"""
		
		# Dot11 Probe Request (to get authentication information if applicable)
		quick_sniff = threading.Thread(target=self.quick_sniff)
		quick_sniff.start()
		sendp(
			RadioTap()/
			Dot11(addr1=self.dest_mac, addr2=self.source_mac, addr3=self.dest_mac)/
			Dot11Auth(seqnum=1), 
			iface=self.interface,
			verbose=False
		)
		quick_sniff.join()
		if rsnInfo is None:  # None explicitly means go get it, leave it '' to proceed with out it
			rsnInfo = self.getRSNInformation(essid)
		if self.lastpacket is None or not self.lastpacket.haslayer(Dot11Auth):
			return 2
		if self.lastpacket.getlayer(Dot11Auth).status != 0:
			return 4
		#Dot11 Association Request
		quick_sniff = threading.Thread(target=self.quick_sniff)
		quick_sniff.start()
		sendp(
			RadioTap()/
			Dot11(addr1=self.bssid, addr2=self.source_mac, addr3=self.bssid, SC=self.__fixSC__(), subtype=0)/
			Dot11AssoReq(cap='ESS+short-preamble+short-slot', listen_interval=10)/
			Dot11Elt(ID=0, info=essid)/
			Dot11Elt(ID=1, info='\x82\x84\x0b\x16\x24\x30\x48\x6c')/
			Dot11Elt(ID=50, info='\x0c\x12\x18\x60')/
			rsnInfo,
			iface=self.interface,
			verbose=False
		)
		quick_sniff.join()
		if self.lastpacket is None or not self.lastpacket.haslayer(Dot11AssoResp):
			return 3
		if self.lastpacket.getlayer(Dot11AssoResp).status != 0:
			return 5
		self.connected = True
		self.sequence = 0
		return 0
	
	def close(self):
		"""
		Disassociate from the access point,  This does not veify that
		the AP received the message and should be considred a
		best-effort attempt.
		errDict = {
			-1:"Not Connected",
			0:"No Error"
		}
		"""
		if not self.connected:
			return -1
		sendp(
			RadioTap()/
			Dot11(addr1=self.dest_mac, addr2=self.source_mac, addr3=self.bssid, SC=self.__fixSC__(), type=0, subtype=12)/
			Dot11Disas(reason=3),
			iface=self.interface,
			verbose=False
		)
		sendp(
			RadioTap()/
			Dot11(addr1=self.dest_mac, addr2=self.source_mac, addr3=self.bssid, SC=self.__fixSC__(), type=0, subtype=12)/
			Dot11Disas(reason=3),
			iface=self.interface,
			verbose=False
		)
		self.connected = False
		return 0
	
	def getRSNInformation(self, essid):
		rsnInfo=None
		sendp(
			RadioTap()/
			Dot11(addr1=self.bssid, addr2=self.source_mac, addr3=self.bssid, SC=self.__fixSC__(), subtype=4)/
			Dot11ProbeReq()/
			Dot11Elt(ID=0, info=essid)/
			Dot11Elt(ID=1, info='\x82\x84\x0b\x16\x24\x30\x48\x6c')/
			Dot11Elt(ID=50, info='\x0c\x12\x18\x60'),
			iface=self.interface,
			verbose=False
		)
		self.sequence += 1
		sniff(iface=self.interface, store=0, timeout=self.timeout, stop_filter=self.__stopfilter__)
		if self.lastpacket is None or not self.lastpacket.haslayer(Dot11ProbeResp):
			return None
		probeResp = self.lastpacket.getlayer(Dot11ProbeResp)
		tmp = probeResp.getlayer(Dot11Elt)
		while tmp:
			if tmp.fields.get('ID') == 48:
				rsnInfo = tmp
				break
			else:
				tmp = tmp.payload
		if rsnInfo is None:
			rsnInfo = ''  # Did not find rsnInfo in probe response.
		else:
			rsnInfo = parseRSNData(rsnInfo.info)
			rsnInfo = buildRSNData(rsnInfo)
			rsnInfo = '\x30' + chr(len(rsnInfo)) + rsnInfo
		return rsnInfo
	
	def recv(self, bufferlen=0):
		"""
		Read a frame and return the information above the Dot11 layer.
		"""
		sniff(iface=self.interface, store=0, timeout=self.timeout, stop_filter=self.__stopfilter__)
		if self.lastpacket:
			return self.lastpacket
		else:
			return None
	
	def send(self, data, dot11_type=2, dot11_subtype=8, FCfield=0x02, raw=True):
		"""
		Send a frame, if raw, insert the data above the Dot11QoS layer.
		"""
		frame = RadioTap()/Dot11(FCfield=FCfield, addr1=self.dest_mac, addr2=self.source_mac, addr3=self.bssid, SC=self.__fixSC__(), type=dot11_type, subtype=dot11_subtype)
		if raw:
			frame = frame/data
		else:
			frame = frame/Dot11QoS()/data
		sendp(frame, iface=self.interface, verbose=False)
		self.sequence += 1
		
	def quick_sniff(self):
		"""
		Sniff function used for threading when packet response is too fast for normal 
		sendp() sniff() syntax
		"""
		sniff(iface=self.interface, stop_filter=self.__stopfilter__, timeout=RESPONSE_TIMEOUT)
		
	def shutdown(self):
		"""
		Shutdown and disassociate from the AP.
		"""
		if self.connected:
			self.close()
		self.__shutdown__ = True

class WirelessStateMachineEAP(WirelessStateMachine):
	"""
	This is to keep the EAP functionality seperate so the core State-
	Machine can be repurposed for other projects.
	"""
		
	def check_eap_type(self,  essid,  eaptype, outer_identity='user', eapol_start=False,rsnInfo=''):
		"""
		Check that an eaptype is supported.
		errDict = {
			0:"supported",
			1:"not supported",
			2:"could not determine",
			3:"identity rejected"
		}
		"""

		eapid = randint(1, 254)
		if eapol_start:
			eapol_start_request = RadioTap()/Dot11(FCfield=0x01, addr1=self.bssid, addr2=self.source_mac, addr3=self.bssid, SC=self.__fixSC__(), type=2, subtype=8)/Dot11QoS()/LLC(dsap=170, ssap=170, ctrl=3)/SNAP(code=0x888e)/EAPOL(version=1, type=1)
			self.sequence += 1
			i = 0
			for i in range(0, EAP_MAX_TRIES):
				quick_sniff = threading.Thread(target=self.quick_sniff)
				quick_sniff.start()
				sendp(eapol_start_request, iface=self.interface, verbose=False)
				quick_sniff.join()
				if not self.lastpacket is None:
					if self.lastpacket.haslayer('EAP'):
						fields = self.lastpacket.getlayer('EAP').fields
						if 'type' in fields and fields['type'] == 1 and fields['code'] == 1:
							i = 0
							eapid = fields['id']
							break
			if i == 2:
				return 2
		eap_identity_response = RadioTap()/Dot11(FCfield=0x01, addr1=self.bssid, addr2=self.source_mac, addr3=self.bssid, SC=self.__fixSC__(), type=2, subtype=8)/Dot11QoS()/LLC(dsap=170, ssap=170, ctrl=3)/SNAP(code=0x888e)/EAPOL(version=1, type=0)/EAP(code=2, type=1, id=eapid, identity=outer_identity)
		eap_legacy_nak = RadioTap()/Dot11(FCfield=0x01, addr1=self.bssid, addr2=self.source_mac, addr3=self.bssid, SC=self.__fixSC__(), type=2, subtype=8)/Dot11QoS()/LLC(dsap=170, ssap=170, ctrl=3)/SNAP(code=0x888e)/EAPOL(version=1, type=0, len=6)/EAP(code=2, type=3, id=eapid + 1, eap_types=[eaptype])
		self.sequence += 1
		
		for i in range(0, EAP_MAX_TRIES):
			quick_sniff = threading.Thread(target=self.quick_sniff)
			quick_sniff.start()
			sendp(eap_identity_response, iface=self.interface, verbose=False)
			quick_sniff.join()
			if not self.lastpacket is None:
				if self.lastpacket.haslayer('EAP'):
					fields = self.lastpacket.getlayer('EAP').fields
					if fields['code'] == 4:	# 4 is a failure
						return 3
					if 'type' in fields and fields['type'] == eaptype:
						return 0
					i = 0
					break
		if i == 2:
			return 2
		for i in range(0, EAP_MAX_TRIES):
			quick_sniff = threading.Thread(target=self.quick_sniff)
			quick_sniff.start()
			sendp(eap_legacy_nak, iface=self.interface, verbose=False)
			quick_sniff.join()
			if not self.lastpacket is None:
				if self.lastpacket.haslayer('EAP'):
					fields = self.lastpacket.getlayer('EAP').fields
					if 'type' in fields and fields['type'] == eaptype:
						return 0
					else:
						return 1
		return 2
