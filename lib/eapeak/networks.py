#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
#
#  lib/eapeak/networks.py
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

# native imports
from base64 import standard_b64encode as b64encode
from xml.sax.saxutils import escape as XMLEscape

# external imports
from M2Crypto import X509
from eapeak.scapylayers.l2 import eap_types as EAP_TYPES

# project imports
from eapeak.common import EXPANDED_EAP_VENDOR_IDS



EAP_TYPES[0] = 'NONE'

class WirelessNetwork:
	"""
	This is an object representing a network.  It holds information
	about a single wireless network including BSSIDs, and Clients (as
	EAPeak Client Objects.

	Each network has a unique SSID/ESSID, but can have multiple BSSIDs.
	"""
	ssid = ''

	def __init__(self, ssid, bssid=''):
		self.bssids = []
		self.clients = {}  # Indexed by client MAC
		self.eapTypes = []
		self.expandedVendorIDs = []
		self.ssid = ssid
		self.x509certs = []
		self.wpsData = None  # This will be changed to an instance of eapeak.parse.wpsDataHolder or a standard dictionary

		if bssid:
			self.bssids.append(bssid)

	def add_BSSID(self, bssid):
		"""
		Add a bssid to be associated with this network.
		"""
		if bssid not in self.bssids:
			self.bssids.append(bssid)

	def add_certificate(self, certificate):
		"""
		Certificates are either packed binary strings in DER format, or
		instances of m2crypto.X509.X509
		"""
		if not isinstance(certificate, X509.X509):
			try:
				certificate = X509.load_cert_string(certificate, X509.FORMAT_DER)
			except:  # pylint: disable=bare-except
				return 1

		newFingerprint = certificate.get_fingerprint()
		for oldcert in self.x509certs:
			if newFingerprint == oldcert.get_fingerprint():
				return -1

		self.x509certs.append(certificate)
		return 0

	def addEapType(self, eapType):
		"""
		Add an eap type to the internal list.
		"""
		if eapType not in self.eapTypes and eapType not in [1, 3]:
			self.eapTypes.append(eapType)

	def add_expanded_vendor_id(self, vendorID):
		"""
		Add a vendor id from an Expanded EAP frame.
		"""
		if vendorID not in self.expandedVendorIDs:
			self.expandedVendorIDs.append(vendorID)

	def add_client(self, clientobj):
		"""
		Add an associated Client Object to the internal list.
		"""
		if not clientobj.mac in self.clients.keys():
			self.clients[clientobj.mac] = clientobj

	def has_client(self, client_mac):
		"""
		Checks that a client has been seen with this network.
		"""
		return client_mac in self.clients.keys()

	def get_client(self, client_mac):
		"""
		Returns a client associated with the give MAC address.
		"""
		if client_mac in self.clients.keys():
			return self.clients[client_mac]
		else:
			return None

	def show(self):
		"""
		This returns a string of human readable information describing
		the network object.
		"""
		output = 'SSID: ' + self.ssid + '\n'
		if self.bssids:
			output += '\tBSSIDs:\n\t\t' + "\n\t\t".join(self.bssids) + '\n'
		if self.eapTypes:
			output += '\tEAP Types:\n'
			for eapType in self.eapTypes:
				if eapType in EAP_TYPES.keys():
					output += '\t\t' + EAP_TYPES[eapType] + '\n'
				else:
					output += '\t\tEAP Type: ' + str(eapType) + '\n'
		if self.expandedVendorIDs:
			output += '\tExpanded EAP Vendor IDs:\n'
			for vendorID in self.expandedVendorIDs:
				if vendorID in EXPANDED_EAP_VENDOR_IDS.keys():
					output += '\t\t' + EXPANDED_EAP_VENDOR_IDS[vendorID] + '\n'
				else:
					output += '\t\tVendor ID: ' + str(vendorID) + '\n'
		if self.wpsData:
			output_control = True
			for piece in ['Manufacturer', 'Model Name', 'Model Number', 'Device Name']:
				if self.wpsData.has_key(piece):
					if output_control:
						output += '\tWPS Information:\n'
						output_control = False
					output += '\t\t' + piece + ': ' + self.wpsData[piece] + '\n'  # pylint: disable=unsubscriptable-object
		if self.clients:
			output += '\tClient Data:\n'
			i = 1
			for client in self.clients.values():
				output += '\t\tClient #' + str(i) + '\n' + client.show(2) + '\n\n'
				i += 1
		if self.x509certs:
			output += '\tCertificates:'
			i = 1
			for cert in self.x509certs:
				output += '\n\t\tCertificate #' + str(i)
				output += '\n\t\tExpiration Date: ' + str(cert.get_not_after())
				data = cert.get_issuer()
				output += '\n\t\tIssuer:'
				for X509_Name_Entry_inst in data.get_entries_by_nid(13): 	# 13 is CN
					output += '\n\t\t\tCN: ' + X509_Name_Entry_inst.get_data().as_text()
				for X509_Name_Entry_inst in data.get_entries_by_nid(18): 	# 18 is OU
					output += '\n\t\t\tOU: ' + X509_Name_Entry_inst.get_data().as_text()

				data = cert.get_subject()
				output += '\n\t\tSubject:'
				for X509_Name_Entry_inst in data.get_entries_by_nid(13): 	# 13 is CN
					output += '\n\t\t\tCN: ' + X509_Name_Entry_inst.get_data().as_text()
				for X509_Name_Entry_inst in data.get_entries_by_nid(18): 	# 18 is OU
					output += '\n\t\t\tOU: ' + X509_Name_Entry_inst.get_data().as_text()
				del data
				output += '\n'
				i += 1
			del cert #pylint: disable=undefined-loop-variable
		return output[:-1]

	def update_SSID(self, ssid):
		self.ssid = ssid

	def get_xml(self):
		"""
		This returns the XML representation of the client object.
		"""
		from xml.etree import ElementTree
		root = ElementTree.Element('wireless-network')
		for bssid in self.bssids:
			ElementTree.SubElement(root, 'BSSID').text = bssid
		tmp = ElementTree.SubElement(root, 'SSID')
		ElementTree.SubElement(tmp, 'type').text = 'Beacon'
		essid = ElementTree.SubElement(tmp, 'essid')
		essid.set('cloaked', 'false')
		essid.text = XMLEscape(self.ssid)
		if self.eapTypes:
			ElementTree.SubElement(tmp, 'eap-types').text = ",".join([str(i) for i in self.eapTypes])
		if self.expandedVendorIDs:
			ElementTree.SubElement(tmp, 'expanded-vendor-ids').text = ",".join([str(i) for i in self.expandedVendorIDs])
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
					tmp.text = b64encode(self.wpsData[info])  # pylint: disable=unsubscriptable-object
		for client in self.clients.values():
			root.append(client.get_xml())
		for cert in self.x509certs:
			tmp = ElementTree.SubElement(root, 'certificate')
			tmp.text = b64encode(cert.as_der())
			tmp.set('encoding', 'DER')
		return root
