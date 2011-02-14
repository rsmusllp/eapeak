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

from scapy.layers.l2 import eap_types as EAP_TYPES
EAP_TYPES[0] = 'NONE'

class WirelessClient:
	authenticated = False
	mac = ''	# this is unique
	bssid = ''	# this is also unique
	
	def __init__(self, bssid, mac):
		self.bssid = bssid
		self.mac = mac
		self.identities = {}			# eaptypes keyed by identities (probably won't have more than one or two, but the identities are unique, allowing for multiple usernames)
		self.eapTypes = []
		self.desiredEapTypes = []		# this isn't used yet, but it's here for the future, it's populated with a NAK is found
		self.datastore = {}				# I love metasploit
	
	def addEapType(self, eapType):
		if eapType not in self.eapTypes and eapType not in [1, 3]:
			self.eapTypes.append(eapType)
			
	def addDesiredEapTypes(self, eapTypes):
		self.desiredEapTypes.extend(eapTypes)

	def addIdentity(self, eaptype, name):
		if not identity in self.identities.keys() and identity:
			self.identities[name] = eaptype

	def show(self, tabs = 0):
		output = ('\t' * tabs) + 'MAC: ' + self.mac + '\n'
		output += ('\t' * tabs) + 'Associated BSSID: ' + self.bssid + '\n'
		
		if self.identities:
			output += ('\t' * tabs) + 'Identities:\n\t' + ('\t' * tabs) + ("\n\t" + ('\t' * tabs)).join(self.identities.keys()) + '\n'
			
		if self.eapTypes:
			output += ('\t' * tabs) + 'EAP Types:\n'
			for eapType in self.eapTypes:
				if eapType in EAP_TYPES.keys():
					output += ('\t' * tabs) + '\t' + EAP_TYPES[eapType] + '\n'
				else:
					output += ('\t' * tabs) + '\tEAP Code: ' + str(eapType) + '\n'
		return output
