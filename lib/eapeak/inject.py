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
from time import sleep
import threading
import Queue

from eapeak.parse import getBSSID, getSource, getDestination
from ipfunc import getHwAddr

from scapy.sendrecv import sniff, sendp
from scapy.layers.dot11 import *
from scapy.layers.l2 import *

RESPONSE_TIMEOUT = 1.5	# time to wait for a response

class SSIDBroadcaster(threading.Thread):
	"""
	This object is a thread-friendly SSID broadcaster
	It's meant to be controlled by the Wireless State Machine
	"""
	def __init__(self, interface, essid, bssid = None):
		threading.Thread.__init__(self)
		self.interface = interface
		self.essid = essid
		if not bssid:
			bssid = getHwAddr(interface)
		self.bssid = bssid.lower()
		self.broadcast_interval = 0.10
		self.channel = "\x06"
		self.capabilities = 'ESS+short-preamble+short-slot'
		self.__shutdown__ = False
		
	def run(self):
		while not self.__shutdown__:
			sendp(RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.bssid, addr3=self.bssid)/Dot11Beacon(cap=self.capabilities)/Dot11Elt(ID="SSID",info=self.essid)/Dot11Elt(ID="Rates",info='\x82\x84\x8b\x96\x24\x30\x48\x6c')/Dot11Elt(ID="DSset",info=self.channel)/Dot11Elt(ID="TIM",info="\x00\x01\x00\x00")/Dot11Elt(ID=42, info="\x04")/Dot11Elt(ID=47, info="\x04")/Dot11Elt(ID=50, info="\x0c\x12\x18\x60"), iface=self.interface, verbose=False)
			sleep(self.broadcast_interval)
			
	def setPrivacy(self, value):
		if value:
			self.capabilities = 'ESS+privacy+short-preamble+short-slot'
		else:
			self.capabilities = 'ESS+short-preamble+short-slot'

class ClientListener(threading.Thread):
	"""
	This object is a thread-friendly listener for Client connection
	attempts.
	
	The backlog corresponds to the size of the queue, if the queu is
	full because the items are not being handled fast enough then new
	association requests will be dropped and lost.
	"""
	def __init__(self, interface, backlog, essid = None, bssid = None):
		threading.Thread.__init__(self)
		self.interface = interface
		self.backlog = backlog
		self.essid = essid
		if not bssid:
			bssid = getHwAddr(interface)
		self.bssid = bssid.lower()
		self.lastpacket = None
		self.client_queue = Queue.Queue(self.backlog)	# FIFO
		self.channel = "\x06"
		self.capabilities = 'ESS+short-preamble+short-slot'
		self.__shutdown__ = False
		
	def __stopfilter__(self, packet):
		if (packet.haslayer('Dot11Auth') or packet.haslayer('Dot11AssoReq')):
			if getBSSID(packet) == self.bssid:
				self.lastpacket = packet
				return True
			return False
		elif packet.haslayer('Dot11ProbeReq'):
			self.lastpacket = packet
			return True
		return False
			
	def setPrivacy(self, value):
		if value:
			self.capabilities = 'ESS+privacy+short-preamble+short-slot'
		else:
			self.capabilities = 'ESS+short-preamble+short-slot'
		
	def run(self):
		while not self.__shutdown__:
			sniff(iface=self.interface, store=0, timeout=RESPONSE_TIMEOUT, stop_filter=self.__stopfilter__)
			if self.lastpacket:
				if self.lastpacket.haslayer('Dot11ProbeReq'):
					ssid = None											# not to be confused with self.essid, they could be different and need to be evaluated
					tmp = self.lastpacket.getlayer(Dot11ProbeReq)
					while tmp:
						tmp = tmp.payload
						if tmp.fields['ID'] == 0:
							ssid = tmp.info
							break
					if ssid == None:
						###
						print "SSID == None"
						continue
					elif ssid == '' and self.essid:
						###
						print "SSID is blank, setting to: " + self.essid
						ssid = self.essid
					###
					print "Received Probe Request for SSID: " + ssid
					if self.essid == None or self.essid == ssid:
						sendp(RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.bssid, addr3=self.bssid)/Dot11ProbeResp(cap=self.capabilities)/Dot11Elt(ID="SSID",info=ssid)/Dot11Elt(ID="Rates",info='\x82\x84\x8b\x96\x24\x30\x48\x6c')/Dot11Elt(ID="DSset",info=self.channel)/Dot11Elt(ID="TIM",info="\x00\x01\x00\x00")/Dot11Elt(ID=42, info="\x04")/Dot11Elt(ID=47, info="\x04")/Dot11Elt(ID=50, info="\x0c\x12\x18\x60"), iface=self.interface, verbose=False)
					self.lastpacket = None
					continue
				clientmac = getSource(self.lastpacket)
				if not self.client_queue.full():
					self.client_queue.put(clientmac, False)
				self.lastpacket = None
				continue

class WirelessStateMachine:
	"""
	This provides a psuedo-socket like object that provides a stack for Dot11 communications using Scapy.
	
	Remember:
	States Are For Smashing
	"""
	def __init__(self, interface, bssid, source_mac = None, dest_mac = None):
		"""
		You must specify a BSSID and a Local MAC address because the entire point of this code is to facilitate stateful connections.
		"""
		if not source_mac:
			source_mac = getHwAddr(interface)
		if not dest_mac:
			dest_mac = bssid
		self.interface = interface
		
		self.bssid = bssid.lower()
		self.source_mac = source_mac.lower()
		self.dest_mac = dest_mac.lower()
		
		self.connected = False	# connected / associated
		self.__shutdown__ = False
		self.sequence = randint(1200, 2000)
		self.lastpacket = None
		
	def __del__(self):
		self.shutdown()
		self.close()
	
	def __unfuckupSC__(self, fragment = 0):
		"""
		This is a reserved method to return the sequence number in a way that is not fucked up by a bug in how the SC field is packed in Scapy.
		"""
		SC = (self.sequence - ((self.sequence >> 4) << 4) << 12) + (fragment << 8) + (self.sequence >> 4) # bit shifts FTW!
		return unpack('<H', pack('>H', SC))[0]
		
	def __stopfilter__(self, packet):
		real_destination = getDestination(packet)
		real_bssid = getBSSID(packet)
		if real_destination == self.source_mac and real_bssid == self.bssid:
			self.lastpacket = packet
			return True
		self.lastpacket = None
		return False
		
	def connect(self, essid):
		"""
		Connect/Associate with an access point.
		errDict = {-1:"Already Connected", 0:"No Error", 1:"Failed To Get Probe Response", 2:"Failed To Get Authentication Response", 3:"Failed To Get Association Response"}
		"""
		# Dot11 Probe Request
		if self.connected == True:
			return -1
		sendp(RadioTap()/Dot11(addr1=self.dest_mac, addr2=self.source_mac, addr3=self.bssid, SC=self.__unfuckupSC__(), type=0, subtype=4, ID=218)/Dot11ProbeReq()/Dot11Elt(ID=0, info=essid)/Dot11Elt(ID=1, info='\x02\x04\x0b\x16\x0c\x12\x18$')/Dot11Elt(ID=50, info='0H`l'), iface=self.interface, verbose=False)
		self.sequence += 1
		sniff(iface=self.interface, store=0, timeout=RESPONSE_TIMEOUT, stop_filter=self.__stopfilter__)
		if self.lastpacket == None:
			return 1
		
		# Dot11 Authentication Request
		sendp(RadioTap()/Dot11(addr1=self.dest_mac, addr2=self.source_mac, addr3=self.bssid, SC=self.__unfuckupSC__())/Dot11Auth(seqnum=1), iface=self.interface, verbose=False)
		self.sequence += 1
		sniff(iface=self.interface, store=0, timeout=RESPONSE_TIMEOUT, stop_filter=self.__stopfilter__)
		if self.lastpacket == None:
			return 2
		
		# Dot11 Association Request
		sendp(RadioTap()/Dot11(addr1=self.dest_mac, addr2=self.source_mac, addr3=self.bssid, SC=self.__unfuckupSC__(), subtype=0)/Dot11AssoReq(cap='ESS+privacy+short-preamble+short-slot', listen_interval=10)/Dot11Elt(ID=0, info=essid)/Dot11Elt(ID=1, info='\x02\x04\x0b\x16\x0c\x12\x18$')/Dot11Elt(ID=50, info='0H`l')/Dot11Elt(ID=48, info='\x01\x00\x00\x0f\xac\x02\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x01\x00\x00')/Dot11Elt(ID=221, info='\x00P\xf2\x02\x00\x01\x00'), iface=self.interface, verbose=False)
		self.sequence += 1
		sniff(iface=self.interface, store=0, timeout=RESPONSE_TIMEOUT, stop_filter=self.__stopfilter__)
		if self.lastpacket == None:
			return 3
		
		self.connected = True
		self.sequence = 0	# reset it
		return 0
		
	def close(self):
		"""
		Disassociate from the access point,  This does not veify that the AP received the message and should be considred a best-effort attempt.
		errDict = {-1:"Not Connected", 0:"No Error"}
		"""
		if not self.connected:
			return -1
		sendp(RadioTap()/Dot11(addr1=self.dest_mac, addr2=self.source_mac, addr3=self.bssid, SC=self.__unfuckupSC__(), type=0, subtype=12)/Dot11Disas(reason=3), iface=self.interface, verbose=False)
		sendp(RadioTap()/Dot11(addr1=self.dest_mac, addr2=self.source_mac, addr3=self.bssid, SC=self.__unfuckupSC__(), type=0, subtype=12)/Dot11Disas(reason=3), iface=self.interface, verbose=False)
		self.connected = False
		return 0
		
	def recv(self):
		"""
		Read a frame and return the information above the Dot11 layer.
		"""
		data = sniff(iface=self.interface, store=1, timeout=RESPONSE_TIMEOUT, stop_filter=self.__stopfilter__)
		if not data:
			return None
		data = data[-1].getlayer(Dot11)
		return data
		
	def send(self, data, dot11_type = 2, dot11_subtype = 8, FCfield = 0x01, raw = True):
		"""
		Send a frame, if raw, insert the data above the Dot11QoS layer.
		"""
		frame = RadioTap()/Dot11(FCfield=FCfield, addr1=self.dest_mac, addr2=self.source_mac, addr3=self.bssid, SC=self.__unfuckupSC__(), type=dot11_type, subtype=dot11_subtype)
		if raw:
			frame = frame/data
		else:
			frame = frame/Dot11QoS()/data
		sendp(frame, iface=self.interface, verbose=False)
		self.sequence += 1
		
	def shutdown(self):
		self.__shutdown__ = True
		if hasattr(self, 'ssid_broadcaster'):							# only applicable in WirelessStateMachineSoftAP
			self.ssid_broadcaster.__shutdown__ = True
			self.ssid_broadcaster.join()
		if hasattr(self, 'client_listener'):							# only applicable in WirelessStateMachineSoftAP
			self.client_listener.__shutdown__ = True
			self.client_listener.join()
		if self.connected:
			self.close()

class WirelessStateMachineEAP(WirelessStateMachine):
	"""
	This is to keep the EAP functionality seperate so the core State-
	Machine can be repurposed for other projects.
	"""
	def check_eap_type(self, eaptype):
		"""
		Check that an eaptype is supported.
		errDict = {0:"supported", 1:"not supported", 2:"could not determine"}
		"""
		eap_identity_response = RadioTap()/Dot11(FCfield=0x01, addr1=self.bssid, addr2=self.source_mac, addr3=self.bssid, SC=self.__unfuckupSC__(), type=2, subtype=8)/Dot11QoS()/LLC(dsap=170, ssap=170, ctrl=3)/SNAP(code=0x888e)/EAPOL(version=1, type=0)/EAP(code=2, type=1, identity='user')
		self.sequence += 1
		eap_legacy_nak = RadioTap()/Dot11(FCfield=0x01, addr1=self.bssid, addr2=self.source_mac, addr3=self.bssid, SC=self.__unfuckupSC__(), type=2, subtype=8)/Dot11QoS()/LLC(dsap=170, ssap=170, ctrl=3)/SNAP(code=0x888e)/EAPOL(version=1, type=0, len=6)/EAP(code=2, type=3, id=1, eap_types=[ eaptype ])
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

class WirelessStateMachineSoftAP(WirelessStateMachine):
	def __init__(self, interface, bssid, essid = None, source_mac = None, dest_mac = None):
		self.essid = essid
		WirelessStateMachine.__init__(self, interface, bssid, source_mac, dest_mac)
		
	def __del__(self):
		self.shutdown()
		
	def listen(self, backlog,  broadcast_interval = 0.25):
		self.backlog = backlog
		self.ssid_broadcaster = SSIDBroadcaster(self.interface, self.essid, self.bssid)
		self.ssid_broadcaster.broadcast_interval = broadcast_interval
		#self.ssid_broadcaster.setPrivacy(True)
		self.ssid_broadcaster.start()
			
	def accept(self):
		if self.__shutdown__: return
		if not hasattr(self, 'client_listener'):
			self.client_listener = ClientListener(self.interface, self.backlog, self.essid, self.bssid)
			self.client_listener.start()
		while not self.__shutdown__:
			try:
				clientmac = self.client_listener.client_queue.get(True, 1)
			except Queue.Empty:
				continue
			sockObj = WirelessStateMachine(self.interface, self.bssid, self.source_mac, clientmac)
			
			sockObj.send(Dot11Auth(seqnum=2), 0, 11, 0, True)
			data = sockObj.recv()
			if not data: continue
			if not data.haslayer(Dot11AssoReq): continue
			sockObj.send(Dot11AssoResp(cap='ESS+short-preamble+short-slot')/Dot11Elt(ID=1, info='\x02\x04\x0b\x16\x0c\x12\x18$')/Dot11Elt(ID=50, info='0H`l'), 0, 1, 0x10, True)
			print 'Sent Data'
			### TEST ###
			sockObj.send(LLC(dsap=0xaa, ssap=0xaa, ctrl=3)/SNAP(code=0x888e)/EAPOL(version=2, type=0)/EAP(code=1, type=1, id=0), FCfield=2, raw=True)
			### END TEST ###
			
			return sockObj, clientmac

	def shutdown(self):
		self.__shutdown__ = True
		if hasattr(self, 'client_listener'):
			self.client_listener.__shutdown__ = True
			self.client_listener.join()
		if hasattr(self, 'ssid_broadcaster'):
			self.ssid_broadcaster.__shutdown__ = True
			self.ssid_broadcaster.join()
