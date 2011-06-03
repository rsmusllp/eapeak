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

__version__ = '0.0.2'

from struct import pack, unpack
from random import randint
from time import sleep
import threading
import Queue

from eapeak.common import getBSSID, getSource, getDestination
from ipfunc import getHwAddr

from scapy.sendrecv import sniff, sendp
from scapy.layers.dot11 import *
from scapy.layers.l2 import *

RESPONSE_TIMEOUT = 3.0	# time to wait for a response
PRIVACY_NONE = 0
PRIVACY_WEP = 1
PRIVACY_WPA = 2

GOOD = '\033[1;32m[+]\033[1;m '
STATUS = '\033[1;34m[*]\033[1;m '
ERROR = '\033[1;31m[-]\033[1;m '

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
		self.broadcast_interval = 0.15
		self.channel = "\x06"
		self.setPrivacy(PRIVACY_NONE)
		self.sequence = randint(1200, 2000)
		self.__shutdown__ = False

	def __unfuckupSC__(self, fragment = 0):
		"""
		This is a reserved method to return the sequence number in a way
		that is not fucked up by a bug in how the SC field is packed in
		Scapy.
		"""
		if self.sequence >= 0xFFF:
			self.sequence = 1
		else:
			self.sequence += 1
		SC = (self.sequence - ((self.sequence >> 4) << 4) << 12) + (fragment << 8) + (self.sequence >> 4) # bit shifts FTW!
		return unpack('<H', pack('>H', SC))[0]
		
	def run(self):
		"""
		This is the thread routine that broadcasts the SSID.
		"""
		while not self.__shutdown__:
			self.beacon.getlayer(Dot11).SC = self.__unfuckupSC__()
			sendp(self.beacon, iface=self.interface, verbose=False)
			sleep(self.broadcast_interval)
			
	def setPrivacy(self, value):
		"""
		Configure the privacy settings for None, WEP, and WPA
		"""
		if value == PRIVACY_NONE:
			self.beacon = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.bssid, addr3=self.bssid)/Dot11Beacon(cap='ESS+short-preamble+short-slot')/Dot11Elt(ID="SSID",info=self.essid)/Dot11Elt(ID="Rates",info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/Dot11Elt(ID="DSset",info=self.channel)/Dot11Elt(ID=42, info="\x04")/Dot11Elt(ID=47, info="\x04")/Dot11Elt(ID=50, info="\x0c\x12\x18\x60")
		elif value == PRIVACY_WEP:
			self.beacon = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.bssid, addr3=self.bssid)/Dot11Beacon(cap='ESS+privacy+short-preamble+short-slot')/Dot11Elt(ID="SSID",info=self.essid)/Dot11Elt(ID="Rates",info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/Dot11Elt(ID="DSset",info=self.channel)/Dot11Elt(ID=42, info="\x04")/Dot11Elt(ID=47, info="\x04")/Dot11Elt(ID=50, info="\x0c\x12\x18\x60")
		elif value == PRIVACY_WPA:
			self.beacon = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.bssid, addr3=self.bssid)/Dot11Beacon(cap='ESS+privacy+short-preamble+short-slot')/Dot11Elt(ID="SSID",info=self.essid)/Dot11Elt(ID="Rates",info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/Dot11Elt(ID="DSset",info=self.channel)/Dot11Elt(ID=221, info="\x00\x50\xf2\x01\x01\x00" + "\x00\x50\xf2\x02" + "\x01\x00" + "\x00\x50\xf2\x02" + "\x01\x00" + "\x00\x50\xf2\x01")/Dot11Elt(ID=42, info="\x00")/Dot11Elt(ID=50, info="\x30\x48\x60\x6c")/Dot11Elt(ID=221, info="\x00\x50\xf2\x02\x01\x01\x84\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00")

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
		self.sequence = randint(1200, 2000)
		self.__shutdown__ = False
		
	def __unfuckupSC__(self, fragment = 0):
		"""
		This is a reserved method to return the sequence number in a way that is not fucked up by a bug in how the SC field is packed in Scapy.
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
		if (packet.haslayer('Dot11Auth') or packet.haslayer('Dot11AssoReq')):
			if getBSSID(packet) == self.bssid and getSource(packet) != self.bssid:
				self.lastpacket = packet
				return True
			return False
		elif packet.haslayer('Dot11ProbeReq'):
			self.lastpacket = packet
			return True
		return False
			
	def setPrivacy(self, value):
		"""
		Configure the privacy settings for None, WEP, and WPA
		"""
		if value == PRIVACY_NONE:
			self.probe_response_template = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.bssid, addr3=self.bssid)/Dot11ProbeResp(cap='ESS+privacy+short-preamble+short-slot')/Dot11Elt(ID="SSID",info='')/Dot11Elt(ID="Rates",info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/Dot11Elt(ID="DSset",info=self.channel)/Dot11Elt(ID=42, info="\x04")/Dot11Elt(ID=47, info="\x04")/Dot11Elt(ID=50, info="\x0c\x12\x18\x60")
		elif value == PRIVACY_WEP:
			self.probe_response_template = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.bssid, addr3=self.bssid)/Dot11ProbeResp(cap='ESS+short-preamble+short-slot')/Dot11Elt(ID="SSID",info='')/Dot11Elt(ID="Rates",info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/Dot11Elt(ID="DSset",info=self.channel)/Dot11Elt(ID=42, info="\x04")/Dot11Elt(ID=47, info="\x04")/Dot11Elt(ID=50, info="\x0c\x12\x18\x60")
		elif value == PRIVACY_WPA:
			self.probe_response_template = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.bssid, addr3=self.bssid)/Dot11ProbeResp(cap='ESS+privacy+short-preamble+short-slot')/Dot11Elt(ID="SSID",info='')/Dot11Elt(ID="Rates",info='\x82\x84\x8b\x96\x0c\x12\x18\x24')/Dot11Elt(ID="DSset",info=self.channel)/Dot11Elt(ID=221, info="\x00\x50\xf2\x01\x01\x00" + "\x00\x50\xf2\x02" + "\x01\x00" + "\x00\x50\xf2\x02" + "\x01\x00" + "\x00\x50\xf2\x01")/Dot11Elt(ID=42, info="\x00")/Dot11Elt(ID=50, info="\x30\x48\x60\x6c")/Dot11Elt(ID=221, info="\x00\x50\xf2\x02\x01\x01\x84\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00")
		
	def run(self):
		"""
		This is the thread routine that handles probe requests and sends
		probe responses when appropriate.
		"""
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
						continue
					elif ssid == '' and self.essid:
						ssid = self.essid
					if self.essid == None or self.essid == ssid:
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
	def __init__(self, interface, bssid, source_mac = None, dest_mac = None):
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
		"""
		This is the stop filter for Scapy to be used to check if the
		packet was sent to this WirelessStateMachine instance.
		"""
		real_destination = getDestination(packet)
		real_bssid = getBSSID(packet)
		real_source = getSource(packet)
		if real_destination == self.source_mac and real_bssid == self.bssid and real_source == self.dest_mac:
			self.lastpacket = packet
			return True
		self.lastpacket = None
		return False
		
	def connect(self, essid):
		"""
		Connect/Associate with an access point.
		errDict = {
			-1:"Already Connected",
			0:"No Error",
			1:"Failed To Get Probe Response",
			2:"Failed To Get Authentication Response",
			3:"Failed To Get Association Response"
		}
		"""
		# Dot11 Probe Request
		if self.connected == True:
			return -1
		sendp(RadioTap()/Dot11(addr1=self.bssid, addr2=self.source_mac, addr3=self.bssid, SC=self.__unfuckupSC__(), type=0, subtype=4, ID=218)/Dot11ProbeReq()/Dot11Elt(ID=0, info=essid)/Dot11Elt(ID=1, info='\x02\x04\x0b\x16\x0c\x12\x18$')/Dot11Elt(ID=50, info='0H`l'), iface=self.interface, verbose=False)
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
		sendp(RadioTap()/Dot11(addr1=self.dest_mac, addr2=self.source_mac, addr3=self.bssid, SC=self.__unfuckupSC__(), type=0, subtype=12)/Dot11Disas(reason=3), iface=self.interface, verbose=False)
		sendp(RadioTap()/Dot11(addr1=self.dest_mac, addr2=self.source_mac, addr3=self.bssid, SC=self.__unfuckupSC__(), type=0, subtype=12)/Dot11Disas(reason=3), iface=self.interface, verbose=False)
		self.connected = False
		return 0
		
	def recv(self):
		"""
		Read a frame and return the information above the Dot11 layer.
		"""
		sniff(iface=self.interface, store=0, timeout=RESPONSE_TIMEOUT, stop_filter=self.__stopfilter__)
		if self.lastpacket:
			return self.lastpacket
		else:
			return None
		
	def send(self, data, dot11_type = 2, dot11_subtype = 8, FCfield = 0x02, raw = True):
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
		"""
		Shutdown and disassociate from the AP.
		"""
		self.__shutdown__ = True
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
		errDict = {
			0:"supported",
			1:"not supported",
			2:"could not determine"
		}
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
	"""
	This is a Python Soft AP object, it manages SSIDBroadcaster and
	ClientListener Threads.
	"""
	def __init__(self, interface, bssid, essid = None):
		self.essid = essid
		self.privacy = PRIVACY_NONE
		self.backlog = 5												# sets a default incase listen() hasn't been called, which may be the case if we're responding to multiple network probes
		self.asso_resp_data = Dot11AssoResp(cap='ESS+short-preamble+short-slot')/Dot11Elt(ID=1, info='\x02\x04\x0b\x16\x0c\x12\x18$')/Dot11Elt(ID=50, info='0H`l')
		WirelessStateMachine.__init__(self, interface, bssid, bssid, None)
		
	def __del__(self):
		self.shutdown()
		
	def listen(self, backlog,  broadcast_interval = 0.25):
		"""
		This sets and starts the SSIDBroadcaster thread and is meant to
		be called once per initialization.
		"""
		self.backlog = backlog
		self.ssid_broadcaster = SSIDBroadcaster(self.interface, self.essid, self.bssid)
		self.ssid_broadcaster.broadcast_interval = broadcast_interval
		self.ssid_broadcaster.setPrivacy(self.privacy)
		self.ssid_broadcaster.start()
			
	def accept(self):
		"""
		This is called after the listen() call and sets up the
		ClientListener, which will respond to probe requests.
		This method can (and often will be) called multiple times.  It
		returns a new WirelessStateMachine instance, pre-configured for
		communication with the client machine.  The client will already
		be associated with the PythonSoftAP.
		
		The Dot11 Authentication frames and Dot11 Association frames are
		transfered in this call, implying the main calling thread is
		blocking.  It is possible that the ClientListener thread may
		queue multiple clients that are attempting to associate with the
		PythonSoftAP but may be lost if accept() is not called again
		before the clients timeout.
		"""
		if self.__shutdown__: return
		if not hasattr(self, 'client_listener'):
			self.client_listener = ClientListener(self.interface, self.backlog, self.essid, self.bssid)
			self.client_listener.setPrivacy(self.privacy)
			self.client_listener.start()
		while not self.__shutdown__:
			if self.client_listener.client_queue.empty():
				continue
			clientMAC = self.client_listener.client_queue.get(True, 1)
			sockObj = WirelessStateMachine(self.interface, self.bssid, self.source_mac, clientMAC)
			
			tries = 3
			sockObj.send(Dot11Auth(seqnum=2), 0, 11, 0, True)
			while tries:
				tries -= 1
				data = sockObj.recv()
				if not data: continue
				if data.haslayer('Dot11AssoReq'): 
					break
				elif data.haslayer(Dot11Auth):
					sockObj.send(Dot11Auth(seqnum=2), 0, 11, 0, True)
			sockObj.send(self.asso_resp_data, 0, 1, 0x10, True)
		
			return sockObj, clientMAC

	def shutdown(self):
		"""
		Shutdown and join the SSIDBroadcaster and ClientListener
		threads.
		"""
		WirelessStateMachine.shutdown(self)
		if hasattr(self, 'client_listener'):
			self.client_listener.__shutdown__ = True
			self.client_listener.join()
		if hasattr(self, 'ssid_broadcaster'):
			self.ssid_broadcaster.__shutdown__ = True
			self.ssid_broadcaster.join()
			
class WirelessStateMachineSoftAPEAP(WirelessStateMachineSoftAP):
	def __init__(self, interface, bssid, essid):
		"""
		EAP version requires an ESSID to target, and automatically
		sets the privacy to WPA.
		"""
		WirelessStateMachineSoftAP.__init__(self, interface, bssid, essid)
		self.privacy = PRIVACY_WPA
		
	def accept(self):
		"""
		This extends the WirelessStateMachineSoftAP accept() method but
		adds in the exchange of EAP identities.
		"""
		# FIXME Get rid of all the debug print messages in this function
		MAX_TRIES = 3
		while not self.__shutdown__:
			(sockObj, clientMAC) = WirelessStateMachineSoftAP.accept(self)
			# print STATUS + "Client " + clientMAC + " Has Associated, Begining EAP Transaction..."
			tries = MAX_TRIES
			while tries:
				tries -= 1
				data = sockObj.recv()
				if not data: continue
				if data.haslayer(EAPOL):
					tries = MAX_TRIES
					break
				elif data.haslayer('Dot11AssoReq'):
					sockObj.send(self.asso_resp_data, 0, 1, 0x10, True)
			if tries != MAX_TRIES:
				# print ERROR + 'Failed To Receive EAPOL'
				continue												# shit failed in that loop up there
			# print STATUS + 'Successfully Received EAPOL'
			
			sockObj.sequence = 1
			while tries:
				tries -= 1
				sockObj.send('\x00\x00'/LLC(dsap=0xaa, ssap=0xaa, ctrl=3)/SNAP(code=0x888e)/EAPOL(version=2, type=0)/EAP(code=1, type=1, id=0, identity='\x00networkid=' + self.essid + ',nasid=AP,portid=0'), FCfield=2, raw=True)
				data = sockObj.recv()
				if data == None:
					continue
				if not data.haslayer(EAP):
					print ERROR + 'Missing EAP Layer'
					continue
				data = data.getlayer(EAP)
				if not 'identity' in data.fields:
					print ERROR + 'Missing Identity'
					continue
				tries = MAX_TRIES
				break
			if tries != MAX_TRIES:
				continue
			# TODO Do something with the username right here
			print GOOD + "Received EAP Identity: {} From Client {}".format(data.identity, clientMAC)
			return sockObj, clientMAC

def runAP():
	"""
	This is a simple method that sets up an new WirelessStateMachine
	instance to broadcast an SSID and create a simple PythonSoftAP
	that associates clients, then ceases communication with them.
	"""
	SSID = 'PythonSoftAP'
	IFACE = 'mon0'
	softap = WirelessStateMachineSoftAPEAP(IFACE, getHwAddr(IFACE), 'PythonSoftAP')
	softap.listen(1, 0.25)
	print "{0}Started EAPwn Soft AP, Version: {1}\n{0}\tESSID: {2}\n{0}\tInterface: {3}".format(STATUS, __version__, SSID, IFACE)
	try:
		while True:
			(clientObj, clientMAC) = softap.accept()
			print GOOD + 'Client ' + clientMAC + ' Has Successfully Finished Associated.'
	except KeyboardInterrupt:
		pass
	except:
		print ERROR + 'An Error Has Occured.'
	print STATUS + 'Shutting Down...'
	softap.shutdown()
	
if __name__ == '__main__':
	runAP()
