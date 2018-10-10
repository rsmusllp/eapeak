#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
#
#  lib/eapeak/clients.py
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

import base64
import binascii
import xml.sax.saxutils

from eapeak.scapylayers.l2 import eap_types as EAP_TYPES

EAP_TYPES[0] = 'NONE'

class WirelessClient:
	"""
	This is an object representing a wireless client.  The MAC address,
	and BSSID are both unique.
	"""
	authenticated = False
	mac = ''
	bssid = ''

	def __init__(self, bssid, mac):
		self.bssid = bssid
		self.mac = mac
		self.identities = {}  # eaptypes keyed by identities (probably won't have more than one or two, but the identities are unique, allowing for multiple usernames)
		self.eapTypes = []
		self.datastore = {}
		self.mschap = []  # Keys are 't' for eap type (int), 'c' for challenge (str), 'r' for response (str), 'i' for identity (str)
		self.wpsData = None # This will be changed to an instance of eapeak.parse.wpsDataHolder or a standard dictionary

	def addEapType(self, eaptype):
		"""
		Add an eap type to the internal list.
		"""
		if eaptype not in self.eapTypes and eaptype > 4:
			self.eapTypes.append(eaptype)

	def add_identity(self, eaptype, identity):
		"""
		Adds identity strings with their associated EAP type that they
		were discovered with.
		"""
		if not identity in self.identities.keys() and identity:
			self.identities[identity] = eaptype

	def add_ms_chap_info(self, eaptype, challenge=None, response=None, identity=None):
		"""
		Adds information to the internal "mschap" list which contains
		dictionaries for each set with keys of:
			't'	eap type (integer)
			'c' challenge (packed binary string)
			'r' response (packed binary string)
			'i' identity (string)
		Challenge and Response strings are packed binary,
		NOT 00:00:00:00:00:00:00:00 or 0000000000000000
		"""
		if not identity:
			identity = 'UNKNOWN'

		if challenge:
			challenge = binascii.hexlify(challenge)
			challenge = ":".join([challenge[y:y + 2] for y in range(0, len(challenge), 2)])
			self.mschap.append({'t': eaptype, 'c': challenge, 'i': identity})
		if response and len(self.mschap):  # Adding a response string, but checking at least one challenge string exists.
			response = binascii.hexlify(response)
			response = ":".join([response[y:y+2] for y in range(0, len(response), 2)])
			for value in self.mschap:
				if not 'r' in value:
					continue
				if response == value['r'] and identity == value['i']:
					return
			resp_obj = self.mschap[len(self.mschap) - 1]  # Get the last response dictionary object
			if identity and identity != resp_obj['i']:
				return 1
			if not 'r' in resp_obj:
				resp_obj['r'] = response
			else:
				return 2

	def show(self, tabs=0):
		"""
		This returns a string of human readable information describing
		the client object, tabs is an optional offset.
		"""
		tab = '    '
		output = (tab * tabs) + 'MAC: ' + self.mac + '\n'
		output += (tab * tabs) + 'Associated BSSID: ' + self.bssid + '\n'

		if self.identities:
			output += (tab * tabs) + 'Identities:\n' + (tab * (tabs + 1)) + ('\n' + (tab * (tabs + 1))).join(self.identities.keys()) + '\n'

		if self.eapTypes:
			output += (tab * tabs) + 'EAP Types:\n'
			for eapType in self.eapTypes:
				if eapType in EAP_TYPES.keys():
					output += (tab * (tabs + 1)) + EAP_TYPES[eapType] + '\n'
				else:
					output += (tab * (tabs + 1)) + 'EAP Type #' + str(eapType) + '\n'
		if self.mschap:
			output_control = True
			for respObj in self.mschap:
				if not 'r' in respObj:  # No response
					continue
				if output_control:
					output += (tab * tabs) + 'MS Chap Challenge & Responses:\n'
					output_control = False
				output += (tab * (tabs + 1)) + 'EAP Type: ' + EAP_TYPES[respObj['t']]
				if respObj['i']:
					output += ', Identity: ' + respObj['i']
				output += '\n'
				output += (tab * (tabs + 2)) + 'C: ' + respObj['c'] + '\n' + (tab * (tabs + 2)) + 'R: ' + respObj['r'] + '\n'
		if self.wpsData:
			output_control = True
			for piece in ['Manufacturer', 'Model Name', 'Model Number', 'Device Name']:
				if self.wpsData.has_key(piece):
					if output_control:
						output += (tab * tabs) + 'WPS Information:\n'
						output_control = False
					output += (tab * (tabs + 1)) + piece + ': ' + self.wpsData[piece] + '\n'  # pylint: disable=unsubscriptable-object
		return output.rstrip()

	def get_xml(self):
		"""
		This returns the XML representation of the client object.
		"""
		from xml.etree import ElementTree
		root = ElementTree.Element('wireless-client')
		ElementTree.SubElement(root, 'client-mac').text = self.mac
		ElementTree.SubElement(root, 'client-bssid').text = self.bssid
		ElementTree.SubElement(root, 'eap-types').text = ",".join([str(i) for i in self.eapTypes])

		for identity, eaptype in self.identities.items():
			tmp = ElementTree.SubElement(root, 'identity')
			tmp.set('eap-type', str(eaptype))
			tmp.text = xml.sax.saxutils.escape(identity)

		for respObj in self.mschap:
			if not 'r' in respObj:
				continue
			tmp = ElementTree.SubElement(root, 'mschap')
			tmp.set('eap-type', str(respObj['t']))
			tmp.set('identity', xml.sax.saxutils.escape(respObj['i']))
			ElementTree.SubElement(tmp, 'challenge').text = respObj['c']
			ElementTree.SubElement(tmp, 'response').text = respObj['r']

		if self.wpsData:
			wps = ElementTree.SubElement(root, 'wps-data')
			for info in ['manufacturer', 'model name', 'model number', 'device name']:
				if self.wpsData.has_key(info):
					tmp = ElementTree.SubElement(wps, info.replace(' ', '-'))
					tmp.text = self.wpsData[info]  # pylint: disable=unsubscriptable-object
			for info in ['uuid', 'registrar nonce', 'enrollee nonce']:  # Values that should be base64 encoded
				if self.wpsData.has_key(info):
					tmp = ElementTree.SubElement(wps, info.replace(' ', '-'))
					tmp.set('encoding', 'base64')
					tmp.text = base64.standard_b64encode(self.wpsData[info])  # pylint: disable=unsubscriptable-object
		return root
