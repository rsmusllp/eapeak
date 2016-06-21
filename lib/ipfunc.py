#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
#
#  lib/ipfunc.py
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
from fcntl import ioctl
from socket import socket, AF_INET, SOCK_DGRAM
import struct
from struct import pack

__doc__ = 'Distributed as part of CORI, http://sourceforge.net/projects/cori-python/\n\nThis module contains misc. ip related functions.'  # pylint: disable=redefined-builtin
__version__ = '1.8'

numbers = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0']


def sanitizeMAC(addr, ciscoFormat=False):
	"""
	This function will return True if the string passed to it looks like a real MAC address.
	ciscoFormat defines whether to expect Cisco\'s xxxx.xxxx.xxxx format.
	"""
	if ciscoFormat:
		char = '.'
		len0 = 3
		len1 = 4
		top = 65536
	else:
		char = ':'
		len0 = 6
		len1 = 2
		top = 256
	addr = addr.split(char)
	if len(addr) != len0:
		return False
	for part in addr:
		if len(part) != len1:
			return False
		try:
			if not int(part, 16) < top:
				return False
		except ValueError:
			return False
	return True

def getHwAddr(ifname):
	"""
	Return the MAC address associated with a network interface, available only on Linux
	"""
	s = socket(AF_INET, SOCK_DGRAM)
	info = ioctl(s.fileno(), 0x8927, pack('256s', ifname[:15]))
	return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]
