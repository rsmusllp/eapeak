"""
	-*- coding: utf-8 -*-
	common.py
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

BSSID_SEARCH_RECURSION = 3
BSSIDPositionMap = { 0:'3', 1:'1', 2:'2', 8:'3', 9:'1', 10:'2' }
SourcePositionMap = { 0:'2', 1:'2', 2:'3', 8:'2', 9:'2', 10:'3' }
DestinationPositionMap = { 0:'1', 1:'3', 2:'1', 8:'1', 9:'3', 10:'1' }

def getBSSID(packet):
	"""
	Returns a BSSID from a Scapy packet object, returns None on failure.
	"""
	tmppacket = packet
	for x in range(0, BSSID_SEARCH_RECURSION):	
		if not 'FCfield' in tmppacket.fields:
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
	"""
	Returns the source MAC address from a Scapy packet object, returns None on failure.
	"""
	tmppacket = packet
	for x in range(0, BSSID_SEARCH_RECURSION):	
		if not 'FCfield' in tmppacket.fields:
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
	"""
	Returns the destination MAC address from a Scapy packet object, returns None on failure.
	"""
	tmppacket = packet
	for x in range(0, BSSID_SEARCH_RECURSION):	
		if not 'FCfield' in tmppacket.fields:
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
	
def checkInterface(ifname):
	"""
	This is a modified function from one I found online to get an IP.
	Only Linux is supported.
	errDict = {-2:"Unsupported OS", -1: "Unknown", 0:"Iface Exists, Has IP", 1:"Iface Exists, No IP", 2:"Iface Does Not Exist"}
	"""
	from socket import socket, AF_INET, SOCK_DGRAM
	from fcntl import ioctl
	from struct import pack
	from os import name
	if name != 'posix':
		return -2
	s = socket(AF_INET, SOCK_DGRAM)
	try:
		addr = ioctl(s.fileno(), 0x8915, pack('256s', ifname[:15]))[20:24]
	except IOError as err:
		if err.errno == 99:
			return 1
		elif err.errno == 19:
			return 2
		return -1
	return 0
