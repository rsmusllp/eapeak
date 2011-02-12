"""
	-*- coding: utf-8 -*-
	clients.py
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

#from binascii import hexlify

class WirelessClient:
	authenticated = False
	mac = ''	# this is unique
	bssid = ''	# this is also unique
	
	def __init__(self, bssid, mac):
		self.bssid = bssid
		self.mac = mac
		self.usernames = []
		self.eapTypes = []
		self.desiredEapTypes = []	# this isn't used yet, but it's here for the future, it's populated with a NAK is found
		self.datastore = {}	# I love metasploit
	
	def addEapType(self, eapType):
		if eapType not in self.eapTypes and eapType not in [1, 3]:
			self.eapTypes.append(eapType)
			
	def addDesiredEapTypes(self, eapTypes):
		self.desiredEapTypes.extend(eapTypes)

	def addUsername(self, name):
		if not name in self.usernames and name:
			self.usernames.append(name)

	def show(self, tabs = 0):
		eaptypeLookup = {
			0: 'None',	# added as per RFC 3748 Page 30 (No Proposed Alternative)
			1: 'Identity',
			2: 'Notification',
			3: 'Legacy Nak', 
			4: 'MD5',
			5: 'One Time Password',
			6: 'Generic Token Card',
			17: 'LEAP', # do not focus on
			25: 'PEAP', 
			43: 'EAP-FAST'
			# still need EAP-TLS
			# still need EAP-TTLS 
		}
		output = ('\t' * tabs) + 'MAC: ' + self.mac + '\n'
		output += ('\t' * tabs) + 'Associated BSSID: ' + self.bssid + '\n'
		
		if self.usernames:
			output += ('\t' * tabs) + 'Usernames:\n\t' + ('\t' * tabs) + ("\n\t" + ('\t' * tabs)).join(self.usernames) + '\n'
			
		if self.eapTypes:
			output += ('\t' * tabs) + 'EAP Types:\n'
			for eapType in self.eapTypes:
				if eapType in eaptypeLookup.keys():
					output += ('\t' * tabs) + '\t' + eaptypeLookup[eapType] + '\n'
				else:
					output += ('\t' * tabs) + '\tEAP Code: ' + str(eapType) + '\n'
				#if eapType == 17 and self.datastore.has_key('LEAP Peer Challenge'):	# LEAP
				#	output += ('\t' * tabs) + '\t\tPeer Challenge: ' + hexlify(self.datastore['LEAP Peer Challenge']) + '\n'
		return output
